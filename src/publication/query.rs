//! <publish> query support
//! see: https://tools.ietf.org/html/rfc8181#section-3.1

use std::io;
use bytes::Bytes;
use uri;
use publication::pubmsg::PublicationMessageError;
use remote::xml::XmlReader;
use remote::xml::Attributes;


//------------ Query ---------------------------------------------------------
#[derive(Debug)]
pub struct Query {
    elements: Vec<QueryElement>
}


impl Query {

    fn decode_publish<R: io::Read>(
        a: &mut Attributes,
        r: &mut XmlReader<R>
    ) -> Result<Publish, PublicationMessageError> {

        let hash = a.take_opt_hex("hash");
        let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
        let tag = a.take_req("tag")?;
        let object = r.take_bytes_characters()?;

        Ok(Publish {
            tag,
            uri,
            hash,
            object
        })
    }


    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Self, PublicationMessageError> {

        let mut elements = vec![];

        loop {
            let e = r.take_list_element(|t, mut a, r| {
                match t.name.as_ref() {
                    "publish" => {
                        let p = Query::decode_publish(&mut a, r)?;
                        Ok(Some(QueryElement::Publish(p)))
                    },
                    _ => {
                        Err(
                            PublicationMessageError::UnexpectedStart(
                                t.name.clone()))
                    }
                }
            })?;
            match e {
                Some(qe) => elements.push(qe),
                None => break
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







