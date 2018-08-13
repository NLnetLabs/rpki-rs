//! <publish> query support
//! see: https://tools.ietf.org/html/rfc8181#section-3.4 and further

//------------ SuccessReply --------------------------------------------------

use std::io;
use bytes::Bytes;
use hex;
use uri;
use publication::pubmsg::MessageError;
use remote::xml::{XmlReader, XmlWriter, XmlWriterError};
use publication::query::PublishElement;

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


//------------ ListReply -----------------------------------------------------

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


//------------ ErrorReply ----------------------------------------------------

/// This type represents the error report as desrcibed in
/// https://tools.ietf.org/html/rfc8181#section-3.5 and 3.6
#[derive(Debug, Eq, PartialEq)]
pub struct ErrorReply {
    errors: Vec<ReportError>
}

impl ErrorReply {

    fn decode_error_text<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Option<String>, MessageError> {

        Ok(Some(r.take_named_element(
            "error_text",
            |a, r| -> Result<String, MessageError> {
                a.exhausted()?;
                Ok(r.take_chars()?)
            }
        )?))
    }

    fn decode_failed_pdu<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Option<PublishElement>, MessageError> {

        Ok(Some(r.take_named_element(
            "failed_pdu",
            |a, r| -> Result<PublishElement, MessageError>{
                a.exhausted()?;
                match PublishElement::decode_opt(r)? {
                    Some(p) => Ok(p),
                    None => {
                        Err(MessageError::MissingContent(
                            "Expected PDU".to_string()))
                    }
                }
            }
        )?))
    }

    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Self, MessageError> {

        let mut errors = vec![];
        loop {
            let e = r.take_opt_element(|t, mut a, r| {
                match t.name.as_ref() {
                    "report_error" => {
                        let error_code = a.take_req("error_code")?;
                        let tag = a.take_req("tag")?;
                        let mut error_text: Option<String> = None;
                        let mut failed_pdu: Option<PublishElement> = None;

                        // There may be two optional elements, the order
                        // may not be determined.
                        for _ in 0..2 {
                            match r.next_start_name() {
                                Some("error_text") => {
                                    error_text = Self::decode_error_text(r)?;
                                },
                                Some("failed_pdu") => {
                                    failed_pdu = Self::decode_failed_pdu(r)?;
                                },
                                _ => { }
                            }
                        }

                        Ok(Some(
                            ReportError{
                                error_code,
                                tag,
                                error_text,
                                failed_pdu
                        }))
                    },
                    _ => {
                        Err(MessageError::UnexpectedStart(t.name.clone()))
                    }
                }
            })?;
            match e {
                Some(e) => errors.push(e),
                None => break
            }
        }
        Ok(ErrorReply{errors})
    }

    pub fn encode_vec<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), XmlWriterError> {

        for e in &self.errors {
            let a = [
                ("error_code", e.error_code.as_ref()),
                ("tag", e.tag.as_ref())
            ];

            w.put_element(
                "report_error",
                Some(&a),
                |w| {

                    match &e.error_text {
                        None => {},
                        Some(t) => {
                            w.put_element(
                                "error_text",
                                None,
                                |w| { w.put_text(t.as_ref())}
                            )?;
                        }
                    }

                    match &e.failed_pdu {
                        None => {},
                        Some(p) => {
                            w.put_element(
                                "failed_pdu",
                                None,
                                |w| { p.encode_vec(w) }
                            )?;
                        }
                    }

                    w.empty()
                }
            )?;
        }

        Ok(())
    }

}



//------------ ReportError ---------------------------------------------------


#[derive(Debug, Eq, PartialEq)]
pub struct ReportError {
    error_code: String,
    tag: String,
    error_text: Option<String>,
    failed_pdu: Option<PublishElement>
}


