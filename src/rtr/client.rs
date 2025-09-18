//! The RTR client.
//!
//! This module implements a generic RTR client through [`Client`]. In order
//! to use the client, you will need to provide a type that implements
//! [`PayloadTarget`] as well as one that implements [`PayloadUpdate`].
//! The former represents the place where all the information received via the
//! RTR client is stored, while the latter receives a set of updates and
//! applies it to the target.
//!
//! For more information on how to use the client, see the [`Client`] type.
use std::{cmp, error, fmt, io};
use std::future::Future;
use tokio::time::{timeout, timeout_at, Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use super::payload::{Action, Payload, Timing};
use super::pdu;
use super::server::MAX_VERSION;
use super::state::State;


//------------ Configuration Constants ---------------------------------------

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The protocol version we initially propose.
const INITIAL_VERSION: u8 = 2;


//------------ PayloadTarget -------------------------------------------------

/// A type that keeps data received via RTR.
///
/// The data of the target consisting of a set of items called VRPs for
/// Validated RPKI Payload. It is modified by atomic updates that add
/// or remove items of the set.
///
/// This trait provides a method to start and apply updates which are
/// collected into a different type that implements the companion
/// [`PayloadUpdate`] trait.
pub trait PayloadTarget {
    /// The type of a single update.
    type Update: PayloadUpdate;

    /// Starts a new update.
    ///
    /// If the update is a for a reset query, `reset` will be `true`, meaning
    /// that when the update is applied, all previous data should be removed.
    fn start(&mut self, reset: bool) -> Self::Update;

    /// Applies an update to the target.
    ///
    /// The data to apply is handed over via `update`. If `reset` is `true`,
    /// the data should replace the current data of the target. Otherwise it
    /// entries should be added and removed according to the action. The
    /// `timing` parameter contains the timing information provided by the
    /// server.
    fn apply(
        &mut self, update: Self::Update, timing: Timing
    ) -> Result<(), PayloadError>;
}


//------------ PayloadUpdate -------------------------------------------------

/// A type that can receive a data update.
///
/// The update happens by repeatedly calling the
/// [`push_update`][Self::push_update] method with a single update as received
/// by the client. The data is not filtered. It may contain duplicates and it
/// may conflict with the current data set. It is the task of the implementor
/// to deal with such situations.
///
/// A value of this type is created via [`PayloadTarget::start`] when the
/// client starts processing an update. If the update succeeds, the value is
/// applied to the target by giving it to [`PayloadTarget::apply`]. If the
/// update fails at any point, the valus is simply dropped.
pub trait PayloadUpdate {
    /// Applies a single updated payload element.
    ///
    /// The `action` argument describes whether the element is to be
    /// announced, i.e., added to the data set, or withdrawn, i.e., removed.
    /// The element itself is given via `payload`.
    ///
    /// If the update is found to be illegal for some reason, the method
    /// returns an error with the appropriate reason.
    fn push_update(
        &mut self, action: Action, payload: Payload
    ) -> Result<(), PayloadError>;
}

impl PayloadUpdate for Vec<(Action, Payload)> {
    fn push_update(
        &mut self, action: Action, payload: Payload
    ) -> Result<(), PayloadError> {
        self.push((action, payload));
        Ok(())
    }
}


//------------ Client --------------------------------------------------------

/// An RTR client.
///
/// The client wraps a socket – represented by the type argument `Sock` which
/// needs to support Tokio’s asynchronous writing and reading – and runs an
/// RTR client over it. All data received will be passed on to a
/// [`PayloadTarget`] of type `Target`.
///
/// The client keeps the socket open until either the server closes the
/// connection, an error happens, or the client is dropped. It will
/// periodically push a new dataset to the target.
pub struct Client<Sock, Target> {
    /// The socket to communicate over.
    sock: Sock,

    /// The target for the VRP set.
    target: Target,

    /// The current synchronisation state.
    ///
    /// If this is `None`, we do a reset query next.
    state: Option<State>,

    /// The RTR version to use.
    ///
    /// If this is `None` we haven’t spoken with the server yet. In this
    /// case, we use 1 and accept any version from the server. Otherwise 
    /// send this version and receving a differing version from the server
    /// is an error as it is not allowed to change its mind halfway.
    version: Option<u8>,

    /// The RTR version to start with.
    initial_version: u8,

    /// The timing parameters reported by the server.
    ///
    /// We use the `refresh` value to determine how long to wait before
    /// requesting an update. The other values we just report to the target.
    timing: Timing,

    /// The next time we should be running.
    ///
    /// If this is None, we should be running now.
    next_update: Option<Instant>,
}

impl<Sock, Target> Client<Sock, Target> {
    /// Creates a new client.
    ///
    /// The client will use `sock` for communicating with the server and
    /// `target` to send updates to.
    ///
    /// If the last state of a connection with this server is known – it can
    /// be determined by calling [`state`] on the client – it can be reused
    /// via the `state` argument. Make sure to also have the matching data in
    /// your target in this case since the there will not necessarily be a
    /// reset update. If you don’t have any state or don’t want to reuse an
    /// earlier session, simply pass `None`.
    ///
    /// [`state`]: #method.state
    pub fn new(
        sock: Sock,
        target: Target,
        state: Option<State>
    ) -> Self {
        Self::with_initial_version(INITIAL_VERSION, sock, target, state)
    }

    /// Creates a new client starting with the given RTR version.
    ///
    /// This is identical [`new`][`Self::new`] but sets the initial version
    /// to the given value. Note that `version` is quietly capped to the
    /// largest version we support.
    ///
    /// The client will downgrade to a lower version if necessary to talk to
    /// the server.
    pub fn with_initial_version(
        initial_version: u8,
        sock: Sock,
        target: Target,
        state: Option<State>
    ) -> Self {
        Client {
            sock, target, state,
            version: None,
            initial_version: cmp::min(initial_version, MAX_VERSION),
            timing: Timing::default(),
            next_update: None,
        }
    }

    /// Returns a reference to the target.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Returns a mutable reference to the target.
    pub fn target_mut(&mut self) -> &mut Target {
        &mut self.target
    }

    /// Converts the client into its target.
    pub fn into_target(self) -> Target {
        self.target
    }

    /// Returns the current state of the session.
    ///
    /// The method will return `None` if there hasn’t been initial state and
    /// there has not been any converstation with the server yet.
    pub fn state(&self) -> Option<State> {
        self.state
    }

    /// Returns the protocol version to use.
    fn version(&self) -> u8 {
        self.version.unwrap_or(self.initial_version)
    }
}

impl<Sock, Target> Client<Sock, Target>
where
    Sock: AsyncRead + AsyncWrite + Unpin,
    Target: PayloadTarget
{
    /// Runs the client.
    ///
    /// The method will keep the client asynchronously running, fetching any
    /// new data that becomes available on the server and pushing it to the
    /// target until either the server closes the connection – in which case
    /// the method will return `Ok(())` –, an error happens – which will be
    /// returned or the future gets dropped.
    pub async fn run(&mut self) -> Result<(), io::Error> {
        loop {
            if let Err(err) = self.step().await {
                if err.kind() == io::ErrorKind::UnexpectedEof {
                    return Ok(())
                }
                else {
                    return Err(err)
                }
            }
        }
    }

    /// Preforms a single update step.
    pub async fn step(
        &mut self
    ) -> Result<(), io::Error> {
        let update = self.update().await?;
        self.apply(update).await
    }

    /// Performs a single update of the client data.
    ///
    /// The method will wait until the next update is due and the request one
    /// single update from the server. It will request a new update object
    /// from the target, apply the update to that object and, if the update
    /// succeeds, return the object.
    pub async fn update(
        &mut self
    ) -> Result<Target::Update, io::Error> {
        if let Some(instant) = self.next_update.take() {
            if let Ok(Err(err)) = timeout_at(
                instant, pdu::SerialNotify::read(&mut self.sock)
            ).await {
                return Err(err)
            }
        }

        if let Some(state) = self.state {
            if let Some(update) = self.serial(state).await? {
                self.next_update = Some(
                    Instant::now() + self.timing.refresh_duration()
                );
                return Ok(update)
            }
        }
        let res = self.reset().await;
        self.next_update = Some(
            Instant::now() + self.timing.refresh_duration()
        );
        res
    }


    /// Perform a serial query.
    ///
    /// Returns some update if the query succeeded and the client should now
    /// wait for a while. Returns `None` if the server reported a restart and
    /// we need to proceed with a reset query. Returns an error
    /// in any other case.
    async fn serial(
        &mut self, state: State
    ) -> Result<Option<Target::Update>, io::Error> {
        let start = loop {
            pdu::SerialQuery::new(
                self.version(), state,
            ).write(&mut self.sock).await?;
            self.sock.flush().await?;
            match self.try_io(FirstSerialReply::read).await? {
                FirstSerialReply::Response(start) => break start,
                FirstSerialReply::Reset => {
                    self.state = None;
                    return Ok(None)
                }
                FirstSerialReply::VersionError(version) => {
                    if self.version.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "version error after successful version \
                             negotiation"
                        ));
                    }
                    // We sent the query with INITIAL_VERSION, so the
                    // returned version must be less.
                    if version >= INITIAL_VERSION {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "version error with larger version"
                        ));
                    }

                    // Try again with the requested version. This will also
                    // force the loop to terminate on next try.
                    self.version = Some(version);
                }
            }
        };
        self.check_version(start.version())?;

        let mut target = self.target.start(false);
        loop {
            match pdu::Payload::read(&mut self.sock).await? {
                Ok(Some(pdu)) => {
                    self.check_version(pdu.version())?;
                    let (action, payload) = match pdu.to_payload() {
                        Ok(some) => some,
                        Err(err) => {
                            err.write(&mut self.sock).await?;
                            return Err(io::Error::other(""));
                        }
                    };
                    if let Err(err) = target.push_update(action, payload) {
                        err.send(
                            self.version(), Some(pdu), &mut self.sock
                        ).await?;
                        return Err(io::Error::other(""));
                    }
                }
                Ok(None) => {
                    // Unsupported but legal payload: ignore.
                }
                Err(end) => {
                    self.check_version(end.version())?;
                    self.state = Some(end.state());
                    if let Some(timing) = end.timing() {
                        self.timing = timing
                    }
                    break;
                }
            }
        }
        Ok(Some(target))
    }

    /// Performs a reset query.
    pub async fn reset(&mut self) -> Result<Target::Update, io::Error> {
        let start = loop {
            pdu::ResetQuery::new(
                self.version()
            ).write(&mut self.sock).await?;
            self.sock.flush().await?;
            match self.try_io(FirstResetReply::read).await? {
                FirstResetReply::Response(start) => break start,
                FirstResetReply::VersionError(version) => {
                    if self.version.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "version error after successful version \
                             negotiation"
                        ));
                    }
                    // We sent the query with INITIAL_VERSION, so the
                    // returned version must be less.
                    if version >= INITIAL_VERSION {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "version error with larger version"
                        ));
                    }

                    // Try again with the requested version. This will also
                    // force the loop to terminate on next try.
                    self.version = Some(version);
                }
            }
        };
        self.check_version(start.version())?;
        let mut target = self.target.start(true);
        loop {
            match pdu::Payload::read(&mut self.sock).await? {
                Ok(Some(pdu)) => {
                    self.check_version(pdu.version())?;
                    let (action, payload) = match pdu.to_payload() {
                        Ok(some) => some,
                        Err(err) => {
                            err.write(&mut self.sock).await?;
                            return Err(io::Error::other(""))
                        }
                    };
                    if let Err(err) = target.push_update(action, payload) {
                        err.send(
                            self.version(), Some(pdu), &mut self.sock
                        ).await?;
                        return Err(io::Error::other(""));
                    }
                }
                Ok(None) => {
                    // Unsupported but legal payload: ignore.
                }
                Err(end) => {
                    self.check_version(end.version())?;
                    self.state = Some(end.state());
                    if let Some(timing) = end.timing() {
                        self.timing = timing
                    }
                    break;
                }
            }
        }
        Ok(target)
    }

    /// Tries to apply an update and sends errors if that fails.
    pub async fn apply(
        &mut self, update: Target::Update
    ) -> Result<(), io::Error> {
        if let Err(err) = self.target.apply(update, self.timing) {
            self.send_error(err).await?;
            Err(io::Error::other(""))
        }
        else {
            Ok(())
        }
    }

    /// Sends an error response to the server.
    pub async fn send_error(
        &mut self, err: PayloadError
    ) -> Result<(), io::Error> {
        err.send(self.version(), None, &mut self.sock).await
    }

    /// Performs some IO operation on the socket.
    ///
    /// The mutable reference to the socket is passed to the closure provided
    /// which does the actual IO. The closure is given `IO_TIMEOUT` to finsih
    /// whatever it is doing. Otherwise it is cancelled and a timeout error
    /// is returned.
    async fn try_io<'a, F, Fut, T>(
        &'a mut self, op: F
    ) -> Result<T, io::Error>
    where
        F: FnOnce(&'a mut Sock) -> Fut,
        Fut: Future<Output = Result<T, io::Error>> + 'a
    {
        match timeout(IO_TIMEOUT, op(&mut self.sock)).await {
            Ok(res) => res,
            Err(_) => {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "server response timed out"
                ))
            }
        }
    }

    /// Checks whether `version` matches the stored version.
    ///
    /// Returns an error if it doesn’t.
    fn check_version(&mut self, version: u8) -> Result<(), io::Error> {
        if let Some(stored_version) = self.version {
            if version != stored_version {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "version has changed"
                ))
            }
            else {
                Ok(())
            }
        }
        else if version > INITIAL_VERSION {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "server requested unsupported protocol version {version}"
                )
            ))
        }
        else {
            self.version = Some(version);
            Ok(())
        }
    }
}


//------------ FirstSerialReply ----------------------------------------------

/// The first reply from a server in response to a serial query.
enum FirstSerialReply {
    /// A cache response. Actual data is to follow.
    Response(pdu::CacheResponse),

    /// A reset response. We need to retry with a reset query.
    Reset,

    /// An unsupported version error.
    ///
    /// The included value is the version reported by the server as part of
    /// the error PDU, i.e., the version that server wants to use.
    VersionError(u8)
}

impl FirstSerialReply {
    /// Reads the first reply from a socket.
    ///
    /// If any other reply than a cache response or reset response is
    /// received or anything else goes wrong, returns an error.
    async fn read<Sock: AsyncRead + Unpin>(
        sock: &mut Sock
    ) -> Result<Self, io::Error> {
        let header = pdu::Header::read(sock).await?;
        match header.pdu() {
            pdu::CacheResponse::PDU => {
                pdu::CacheResponse::read_payload(
                    header, sock
                ).await.map(FirstSerialReply::Response)
            }
            pdu::CacheReset::PDU => {
                pdu::CacheReset::read_payload(
                    header, sock
                ).await.map(|_| FirstSerialReply::Reset)
            }
            pdu::Error::PDU
                if header.session()
                    == pdu::ErrorCode::UNSUPPORTED_PROTOCOL_VERSION
            => {
                pdu::Error::skip_payload(header, sock).await?;
                Ok(Self::VersionError(header.version()))
            }
            pdu::Error::PDU => {
                Err(io::Error::other(
                    format!("server reported error {}", header.session())
                ))
            }
            pdu => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected PDU {pdu}")
                ))
            }
        }
    }
}


//------------ FirstResetReply -----------------------------------------------

/// The first reply from a server in response to a reset query.
enum FirstResetReply {
    /// A cache response. Actual data is to follow.
    Response(pdu::CacheResponse),

    /// An unsupported version error.
    ///
    /// The included value is the version reported by the server as part of
    /// the error PDU, i.e., the version that server wants to use.
    VersionError(u8)
}

impl FirstResetReply {
    /// Reads the first reply from a socket.
    ///
    /// If any other reply than a cache response or reset response is
    /// received or anything else goes wrong, returns an error.
    async fn read<Sock: AsyncRead + Unpin>(
        sock: &mut Sock
    ) -> Result<Self, io::Error> {
        let header = pdu::Header::read(sock).await?;
        match header.pdu() {
            pdu::CacheResponse::PDU => {
                pdu::CacheResponse::read_payload(
                    header, sock
                ).await.map(Self::Response)
            }
            pdu::Error::PDU
                if header.session()
                    == pdu::ErrorCode::UNSUPPORTED_PROTOCOL_VERSION
            => {
                pdu::Error::skip_payload(header, sock).await?;
                Ok(Self::VersionError(header.version()))
            }
            pdu::Error::PDU => {
                Err(io::Error::other(
                    format!("server reported error {}", header.session())
                ))
            }
            pdu => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected PDU {pdu}")
                ))
            }
        }
    }
}


//------------ PayloadError --------------------------------------------------

/// A received payload update was not acceptable.
#[derive(Clone, Copy, Debug)]
pub enum PayloadError {
    /// A nonexisting record was withdrawn.
    UnknownWithdraw,

    /// An existing record was announced again.
    DuplicateAnnounce,

    /// The record is corrupt.
    Corrupt,

    /// An internal error in the receiver happend.
    Internal,
}

impl PayloadError {
    /// Returns the RTR error code corresponding to the error reason.
    fn error_code(self) -> u16 {
        match self {
            PayloadError::UnknownWithdraw => 6,
            PayloadError::DuplicateAnnounce => 7,
            PayloadError::Corrupt => 0,
            PayloadError::Internal => 1
        }
    }

    /// Sends the error as a RTR error PDU.
    async fn send(
        self, version: u8, pdu: Option<pdu::Payload>,
        sock: &mut (impl AsyncWrite + Unpin)
    ) -> Result<(), io::Error> {
        match pdu {
            Some(pdu) => {
                pdu::Error::new(
                    version, self.error_code(), pdu.as_partial_slice(), ""
                ).write(sock).await
            }
            None => {
                pdu::Error::new(
                    version, self.error_code(), "", ""
                ).write(sock).await
            }
        }
    }
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            PayloadError::UnknownWithdraw => "withdrawal of non-existing item",
            PayloadError::DuplicateAnnounce => "duplicate announcement",
            PayloadError::Corrupt => "corrup data set",
            PayloadError::Internal => "internal error",
        })
    }
}

impl error::Error for PayloadError { }

