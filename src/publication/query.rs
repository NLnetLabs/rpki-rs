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
use remote::xml::XmlWriterError;


//------------ ListQuery -----------------------------------------------------

/// Type representing the list query as described in
/// https://tools.ietf.org/html/rfc8181#section-2.3
#[derive(Debug, Eq, PartialEq)]
pub struct ListQuery;

impl ListQuery {

    pub fn decode<R: io::Read>(r: &mut XmlReader<R>)
        -> Result<Self, MessageError> {
        r.take_named_element("list", |_, r| { r.take_empty()})?;
        Ok(ListQuery)
    }

    pub fn encode_vec<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), XmlWriterError> {

        w.put_element(
            "list",
            None,
            |w| { w.empty() }
        )?;

        Ok(())
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
    pub fn encode_vec<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), XmlWriterError> {

        for e in &self.elements {
            e.encode_vec(w)?;
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

    pub fn encode_vec<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), XmlWriterError> {

        match self {
            PublishElement::Publish(p)   => { p.encode_vec(w)?; },
            PublishElement::Update(u)    => { u.encode_vec(w)?; },
            PublishElement::Withdraw(wi) => { wi.encode_vec(w)?; }
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

    fn encode_vec<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), XmlWriterError> {

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

    fn encode_vec<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), XmlWriterError> {

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

    fn encode_vec<W: io::Write>(&self, w: &mut XmlWriter<W>)
        -> Result<(), XmlWriterError> {

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
}





