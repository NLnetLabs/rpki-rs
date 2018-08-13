//! <publish> query support
//! see: https://tools.ietf.org/html/rfc8181#section-3.4 and further

//------------ SuccessReply --------------------------------------------------

use std::io;
use bytes::Bytes;
use hex;
use uri;
use publication::pubmsg::MessageError;
use remote::xml::{XmlReader, XmlWriter, XmlWriterError};

/// This type represents the success reply as desribed in
/// https://tools.ietf.org/html/rfc8181#section-3.4
#[derive(Debug, Eq, PartialEq)]
pub struct SuccessReply;

impl SuccessReply {

    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Self, MessageError> {
        r.take_named_element("success", |_, r| { r.take_empty() })?;
        Ok(SuccessReply)
    }

    pub fn encode_vec<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), XmlWriterError> {

        w.put_element(
            "success",
            None,
            |w| { w.empty() }
        )?;

        Ok(())
    }
}

/// This type represents the list reply as desrcibed in
/// https://tools.ietf.org/html/rfc8181#section-2.3
#[derive(Debug, Eq, PartialEq)]
pub struct ListReply {
    elements: Vec<ListElement>
}

#[derive(Debug, Eq, PartialEq)]
pub struct ListElement {
    hash: Bytes,
    uri: uri::Rsync
}

impl ListReply {

    pub fn decode<R: io::Read>(r: &mut XmlReader<R>) -> Result<Self, MessageError> {

        let mut elements = vec![];

        loop {
            let e = r.take_opt_element(|t, mut a, _r| {
                match t.name.as_ref() {
                    "list" => {
                        let hash = a.take_req_hex("hash")?;
                        let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
                        a.exhausted()?;

                        Ok(Some(ListElement{hash, uri}))
                    },
                    _ => {
                        Err(MessageError::UnexpectedStart(t.name.clone()))
                    }
                }
            })?;

            match e {
                Some(e) => elements.push(e),
                None    => break
            }
        }
        Ok(ListReply{elements})
    }

    pub fn encode_vec<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), XmlWriterError> {

        for l in &self.elements {
            let hash = hex::encode(&l.hash);
            let uri = l.uri.to_string();

            w.put_element(
                "list",
                Some(&[("hash", hash.as_ref()), ("uri", uri.as_ref())]),
                |w| { w.empty() }
            )?;
        }

        Ok(())
    }


}
