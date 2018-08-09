//! <publish> query support, see: https://tools.ietf.org/html/rfc8181#section-3.1

use std::io;
use bytes::Bytes;
use uri;
use publication::pubmsg::PublicationMessageError;
use remote::xml::XmlReader;


//------------ Query ---------------------------------------------------------
#[derive(Debug)]
pub struct Query {
    elements: Vec<QueryElement>
}


impl Query {

    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Self, PublicationMessageError> {

        let mut elements = vec![];

        loop {
            match r.next_start()? {
                Some(e) => {
                    let (mut xml_tag, mut att) = e;

                    match xml_tag.name.as_ref() {
                        "publish" => {
                            let hash = att.take_opt_hex("hash");
                            let uri = uri::Rsync::from_string(
                                att.take_req("uri")?)?;
                            let tag = att.take_req("tag")?;
                            let object = r.take_bytes_characters()?;

                            r.expect_close(xml_tag)?;

                            let mut p = Publish {
                                tag,
                                uri,
                                hash,
                                object
                            };

                            elements.push(QueryElement::Publish(p));
                        }
                        _ => {
                            return Err(
                                PublicationMessageError::UnexpectedXmlStartTag(
                                    xml_tag.name))
                        }
                    }

                }
                None => { break; }
            }
        }

        Ok(Query{elements})
    }

}



//------------ Query ---------------------------------------------------------
#[derive(Debug)]
pub enum QueryElement {
    Publish(Publish),
    Withdraw(Withdraw)
}


//------------ Publish -------------------------------------------------------
#[derive(Debug)]
pub struct Publish {
    hash: Option<Bytes>,
    tag: String,
    uri: uri::Rsync,
    object: Bytes
}


//------------ Withdraw ------------------------------------------------------
#[derive(Debug)]
pub struct Withdraw {
    hash: Option<Bytes>,
    tag: String,
    uri: uri::Rsync
}







