//! <publish> query support
//! see: https://tools.ietf.org/html/rfc8181#section-3.1 and further

use std::io;
use bytes::Bytes;
use hex;
use uri;
use publication::pubmsg::MessageError;
use remote::xml::XmlReader;
use remote::xml::Attributes;
use remote::xml::XmlWriter;
use publication::pubmsg::Message;
use publication::pubmsg::QueryMessage;
use ring::digest;


//------------ ListQuery -----------------------------------------------------

/// Type representing the list query as described in
/// https://tools.ietf.org/html/rfc8181#section-2.3
#[derive(Debug, Eq, PartialEq)]
pub struct ListQuery;

impl ListQuery {
    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Self, MessageError> {
        r.take_named_element("list", |_, r| { r.take_empty() })?;
        Ok(ListQuery)
    }

    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), io::Error> {
        w.put_element(
            "list",
            None,
            |w| { w.empty() }
        )?;

        Ok(())
    }

    /// Creates a ListQuery inside a full Message enum type.
    ///
    /// The `Message` type is used because it's this outer type that needs
    /// to be encoded and included in protocol messages.
    pub fn new_message() -> Message {
        Message::QueryMessage(QueryMessage::ListQuery(ListQuery))
    }
}


//------------ PublishQuery --------------------------------------------------

/// Type representing a multi element query as described in
/// https://tools.ietf.org/html/rfc8181#section-3.7
#[derive(Debug, Eq, PartialEq)]
pub struct PublishQuery {
    elements: Vec<PublishElement>
}


impl PublishQuery {

    fn decode_publish<R: io::Read>(
        a: &mut Attributes,
        r: &mut XmlReader<R>
    ) -> Result<PublishElement, MessageError> {

        let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
        let tag = a.take_req("tag")?;
        let object = r.take_bytes_characters()?;

        let res = match a.take_opt_hex("hash") {
            Some(hash) => {
                Ok(PublishElement::Update(Update{
                    hash, tag, uri, object
                }))
            },
            None => {
                Ok(PublishElement::Publish(Publish{
                    tag, uri, object
                }))
            }
        };

        a.exhausted()?;
        res
    }

    fn decode_withdraw(a: &mut Attributes)
        -> Result<PublishElement, MessageError> {

        let hash = a.take_req_hex("hash")?;
        let uri = uri::Rsync::from_string(a.take_req("uri")?)?;
        let tag = a.take_req("tag")?;

        a.exhausted()?;

        Ok(PublishElement::Withdraw(Withdraw {
            hash,
            tag,
            uri
        }))
    }


    /// Decodes a query XML structure. Expects that the outer <msg> element
    /// is processed by PublicationMessage::decode
    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Self, MessageError> {

        let mut elements = vec![];

        loop {
            let e = PublishElement::decode_opt(r)?;
            match e {
                Some(qe) => elements.push(qe),
                None => break
            }
        }
        Ok(PublishQuery {elements})
    }

    /// Encodes an existing multi-element PublishQuery to XML.
    /// Note that a PublishQuery should be encoded through the
    /// PublicationMessage::encode function.
    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), io::Error> {

        for e in &self.elements {
            e.encode(w)?;
        }
        Ok(())
    }

}


//------------ PublishElement ------------------------------------------------

/// This type represents the three types of requests that can be included
/// in a multi-element query.
#[derive(Debug, Eq, PartialEq)]
pub enum PublishElement {
    Publish(Publish),
    Update(Update),
    Withdraw(Withdraw)
}

impl PublishElement {

    pub fn decode_opt<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Option<Self>, MessageError> {

        r.take_opt_element(|t, mut a, r| {
            match t.name.as_ref() {
                "publish"  => {
                    Ok(Some(PublishQuery::decode_publish(&mut a, r)?)) },
                "withdraw" => {
                    Ok(Some(PublishQuery::decode_withdraw(&mut a)?)) },
                _ => {
                    Err(MessageError::UnexpectedStart(t.name.clone()))
                }
            }
        })
    }

    pub fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), io::Error> {

        match self {
            PublishElement::Publish(p)   => { p.encode(w)?; },
            PublishElement::Update(u)    => { u.encode(w)?; },
            PublishElement::Withdraw(wi) => { wi.encode(w)?; }
        }
        Ok(())
    }

}


//------------ Update -------------------------------------------------------

/// Represents a publish element, that updates an existing object
/// https://tools.ietf.org/html/rfc8181#section-3.2
#[derive(Debug, Eq, PartialEq)]
pub struct Update {
    hash: Bytes,
    tag: String,
    uri: uri::Rsync,
    object: Bytes
}

impl Update {

    fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), io::Error> {

        let uri = self.uri.to_string();
        let enc = hex::encode(&self.hash);

        let a = [
            ("tag", self.tag.as_ref()),
            ("hash", enc.as_ref()),
            ("uri", uri.as_ref())
        ];


        w.put_element(
            "publish",
            Some(&a),
            |w| {
                w.put_blob(&self.object)
            }
        )
    }

    pub fn publish(old: &Bytes, new: &Bytes, uri: uri::Rsync) -> PublishElement {
        let tag  = hex::encode(hash(new));
        let hash = hash(old);
        PublishElement::Update(Update { hash, tag, uri, object: new.clone() })
    }
}


//------------ Publish -------------------------------------------------------

/// Represents a publish element, that does not update any existing object
/// https://tools.ietf.org/html/rfc8181#section-3.1
#[derive(Debug, Eq, PartialEq)]
pub struct Publish {
    tag: String,
    uri: uri::Rsync,
    object: Bytes
}

impl Publish {

    fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), io::Error> {

        let uri =  self.uri.to_string();

        let a = [
            ("tag", self.tag.as_ref()),
            ("uri", uri.as_ref()),
        ];

        w.put_element(
            "publish",
            Some(&a),
            |w| {
                w.put_blob(&self.object)
            }
        )
    }

    pub fn publish(object: &Bytes, uri: uri::Rsync) -> PublishElement {
        let hash = hash(object);
        let tag  = hex::encode(&hash);
        PublishElement::Publish(Publish { tag, uri, object: object.clone() })
    }
}


//------------ Withdraw ------------------------------------------------------

/// Represents a withdraw element that removes an object from the repository
/// https://tools.ietf.org/html/rfc8181#section-3.3
#[derive(Debug, Eq, PartialEq)]
pub struct Withdraw {
    hash: Bytes,
    tag: String,
    uri: uri::Rsync
}

impl Withdraw {

    fn encode<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), io::Error> {

        let uri =  self.uri.to_string();
        let enc = hex::encode(self.hash.clone());

        let a = [
            ("hash", enc.as_ref()),
            ("tag", self.tag.as_ref()),
            ("uri", uri.as_ref())
        ];

        w.put_element(
            "withdraw",
            Some(&a),
            |w| {
                w.empty()
            }
        )
    }

    pub fn publish(object: &Bytes, uri: uri::Rsync) -> PublishElement {
        let hash = hash(object);
        let tag  = hex::encode(&hash);
        PublishElement::Withdraw(Withdraw { hash, tag, uri })
    }

}

fn hash(object: &Bytes) -> Bytes {
    Bytes::from(digest::digest(
        &digest::SHA256,
        object.as_ref()
    ).as_ref())
}


pub struct PublishQueryBuilder {
    elements: Vec<PublishElement>
}

impl PublishQueryBuilder {
    pub fn add(&mut self, e: PublishElement) {
        self.elements.push(e)
    }

    pub fn new() -> Self {
        PublishQueryBuilder { elements: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        PublishQueryBuilder { elements: Vec::with_capacity(n)}
    }

    pub fn build(self) -> QueryMessage {
        QueryMessage::PublishQuery(PublishQuery { elements: self.elements })
    }
}




//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str;
    use uri::Rsync;

    fn rsync_uri(s: &str) -> Rsync {
        Rsync::from_str(s).unwrap()
    }


    #[test]
    fn should_create_list_query() {
        match ListQuery::new_message() {
            Message::QueryMessage(QueryMessage::ListQuery(_)) => {
                // ListQuery has no content, nothing to check here.
            }
            _ => panic!("Got the wrong return value")
        }
    }

    #[test]
    fn should_create_publish_query() {
        let object = Bytes::from_static(include_bytes!("../../test/remote/cms-ta.cer"));
        let object2 = Bytes::from_static(include_bytes!("../../test/remote/pdu.200.der"));
        let w = Withdraw::publish(&object, rsync_uri("rsync://host/path/cms-ta.cer"));
        let p = Publish::publish(&object, rsync_uri("rsync://host/path/cms-ta.cer"));
        let u = Update::publish(&object, &object2, rsync_uri("rsync://host/path/cms-ta.cer"));

        let mut b = PublishQueryBuilder::with_capacity(3);
        b.add(w);
        b.add(p);
        b.add(u);
        let pq = b.build();
        let m = Message::new_query(pq);
        let vec = m.encode_vec();
        let produced_xml = str::from_utf8(&vec).unwrap();
        let expected_xml = include_str!("../../test/publication/generated/publish-builder-result.xml");

        assert_eq!(produced_xml, expected_xml);
    }


}


