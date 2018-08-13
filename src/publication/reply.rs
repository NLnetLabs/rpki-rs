//! <publish> query support
//! see: https://tools.ietf.org/html/rfc8181#section-3.4 and further

//------------ SuccessReply --------------------------------------------------

use std::io;
use remote::xml::XmlReader;
use publication::pubmsg::MessageError;
use remote::xml::XmlWriter;
use remote::xml::XmlWriterError;

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
