use std::time::Instant;

use crate::packet::Address;
use crate::request::RequestId;

pub struct Destination {
    pub address: Address,
    pub app_data: Option<Vec<u8>>,
    pub hops: u8,
    pub last_seen: Instant,
}

pub(crate) enum PendingAction {
    SendRaw {
        destination: Address,
        data: Vec<u8>,
    },
    Request {
        destination: Address,
        path: String,
        data: Vec<u8>,
    },
    Respond {
        request_id: RequestId,
        data: Vec<u8>,
    },
    Announce {
        app_data: Option<Vec<u8>>,
    },
    RequestPath {
        destination: Address,
    },
}

pub struct NodeHandle<'a> {
    pub(crate) service_address: Address,
    pub(crate) destinations: &'a [Destination],
    pub(crate) pending: Vec<PendingAction>,
}

impl NodeHandle<'_> {
    pub fn send_raw(&mut self, destination: Address, data: &[u8]) {
        self.pending.push(PendingAction::SendRaw {
            destination,
            data: data.to_vec(),
        });
    }

    pub fn request(&mut self, destination: Address, path: &str, data: &[u8]) {
        self.pending.push(PendingAction::Request {
            destination,
            path: path.to_string(),
            data: data.to_vec(),
        });
    }

    pub fn respond(&mut self, request_id: RequestId, data: &[u8]) {
        self.pending.push(PendingAction::Respond {
            request_id,
            data: data.to_vec(),
        });
    }

    pub fn announce(&mut self) {
        self.pending
            .push(PendingAction::Announce { app_data: None });
    }

    pub fn announce_with_app_data(&mut self, app_data: &[u8]) {
        self.pending.push(PendingAction::Announce {
            app_data: Some(app_data.to_vec()),
        });
    }

    pub fn request_path(&mut self, destination: Address) {
        self.pending
            .push(PendingAction::RequestPath { destination });
    }

    pub fn destinations(&self) -> impl Iterator<Item = &Destination> {
        self.destinations.iter()
    }
}

pub trait Service {
    fn name(&self) -> &str;

    fn paths(&self) -> Vec<&str> {
        vec![]
    }

    #[allow(unused_variables)]
    fn on_raw(&mut self, handle: &mut NodeHandle, from: Address, data: &[u8]) {}

    #[allow(unused_variables)]
    fn on_request(
        &mut self,
        handle: &mut NodeHandle,
        request_id: RequestId,
        from: Address,
        path: &str,
        data: &[u8],
    ) {
    }

    #[allow(unused_variables)]
    fn on_response(&mut self, handle: &mut NodeHandle, from: Address, data: &[u8]) {}

    #[allow(unused_variables)]
    fn on_destinations_changed(&mut self, handle: &mut NodeHandle) {}
}
