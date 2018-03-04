use std::collections::HashMap;
use errors::Result;

// A Service entry Key in a ServiceRegistry
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct ServiceKey(u32);

// A list of services that a client is interested in and the last change seen
#[derive(Debug)]
pub struct ClientServices {
    service_list: Vec<ServiceKey>,
    change_count: u32,
}

#[derive(Debug)]
struct ServiceRegistry {
    lookup: HashMap<String, u32>,
    table: Vec<String>,
}

// Return result of the first delta call for a client given a full list of service id's and versions
#[derive(Debug)]
pub struct ServiceClientInit {
    pub service_list: ClientServices,
    pub delta: Vec<Service>,
}

impl ServiceRegistry {
    fn new() -> ServiceRegistry {
        ServiceRegistry {
            lookup: HashMap::new(),
            table: Vec::new(),
        }
    }

    // Add's a new service to the lookup table, returns the existing key if the service already
    // exists
    fn add_service(&mut self, service_id: String) -> ServiceKey {
        if let Some(v) = self.lookup.get(&service_id) {
            return ServiceKey(v.clone());
        }
        let i = self.table.len();
        self.table.push(service_id.clone());
        self.lookup.insert(service_id, i as u32);
        ServiceKey(i as u32)
    }

    fn lookup_id(&self, key: ServiceKey) -> Option<String> {
        self.table.get(key.0 as usize).cloned()
    }

    fn lookup_key(&self, service_id: String) -> Option<ServiceKey> {
        self.lookup.get(&service_id).cloned().map(ServiceKey)
    }
}

// An individual service and the current change count
#[derive(Debug)]
struct ServiceRevision {
    change_count: u32,
    service: ServiceKey,
}

// A provided Service/Version used for `ChangeList` initialization, client comparisons, and
// outgoing deltas
#[derive(Clone, Debug, PartialEq)]
pub struct Service {
    service_id: String,
    version: String,
}

// ServiceChangeTracker tracks the services, their change_count, and the service lookup registry
#[derive(Debug)]
pub struct ServiceChangeTracker {
    service_list: Vec<ServiceRevision>,
    service_registry: ServiceRegistry,
    service_versions: HashMap<ServiceKey, String>,
    change_count: u32,
}

impl ServiceChangeTracker {
    /// Creates a new `ServiceChangeTracker` initialized with the provided `services`.
    pub fn new(services: Vec<Service>) -> ServiceChangeTracker {
        let mut svc_change_tracker = ServiceChangeTracker {
            service_list: Vec::new(),
            service_registry: ServiceRegistry::new(),
            service_versions: HashMap::new(),
            change_count: 0,
        };
        for srv in services {
            let key = svc_change_tracker.service_registry.add_service(srv.service_id);
            svc_change_tracker.service_versions.insert(key, srv.version);
        }
        svc_change_tracker
    }

    /// Add a new service to the ServiceChangeTracker, triggering a change_count increase.
    /// Note: If the service already exists, it will be updated instead.
    pub fn add_service(&mut self, service: Service) {
        if let Ok(_) = self.update_service(service.clone()) {
            return;
        }
        self.change_count += 1;
        let key = self.service_registry.add_service(service.service_id);
        self.service_versions.insert(key, service.version);
        self.service_list.push(ServiceRevision {
            change_count: self.change_count,
            service: key,
        });
    }

    /// Update a `service` to a new revision, triggering a change_count increase.
    ///
    /// Returns an error if the `service` was never initialized/added.
    pub fn update_service(&mut self, service: Service) -> Result<u32> {
        let key = self.service_registry
            .lookup_key(service.service_id)
            .ok_or("Service not found")?;

        if let Some(ver) = self.service_versions.get_mut(&key) {
            if *ver == service.version {
                return Ok(self.change_count);
            }
            *ver = service.version;
        } else {
            return Err("Service not found".into());
        }

        // Check to see if this service has been updated since initialization
        let svc_index = self.service_list.iter()
            .enumerate()
            .filter_map(|(i, svc)| if svc.service == key { Some(i) } else { None })
            .nth(0);
        self.change_count += 1;
        if let Some(svc_index) = svc_index {
            let mut svc = self.service_list.remove(svc_index);
            svc.change_count = self.change_count;
            self.service_list.push(svc);
        } else {
            self.service_list.push(
                ServiceRevision {
                    change_count: self.change_count,
                    service: key,
                }
            )
        }
        Ok(self.change_count)
    }

    /// Returns the new service versions since the provided `client_set`.
    pub fn change_count_delta(&self, client_set: &mut ClientServices) -> Option<Vec<Service>> {
        if self.change_count <= client_set.change_count {
            return None;
        }
        let mut svc_iter = self.service_list.iter().rev();
        let mut svc_delta = Vec::new();
        while let Some(svc) = svc_iter.next() {
            if svc.change_count <= client_set.change_count {
                break;
            }
            if let Some(ver) = self.service_versions.get(&svc.service) {
                if let Some(svc_id) = self.service_registry.lookup_id(svc.service) {
                    svc_delta.push(Service {
                        service_id: svc_id,
                        version: (*ver).clone(),
                    });
                }
            }
        }
        client_set.change_count = self.change_count;
        if svc_delta.is_empty() {
            None
        } else {
            Some(svc_delta)
        }
    }

    /// Returns a delta for `services` that are out of date with the latest version and a new
    /// `ClientSet``.
    pub fn service_delta(&self, services: Vec<Service>) -> ServiceClientInit {
        let mut svc_list = Vec::new();
        let mut svc_delta = Vec::new();
        for svc in services.iter() {
            if let Some(svc_key) = self.service_registry.lookup_key(svc.service_id.clone()) {
                if let Some(ver) = self.service_versions.get(&svc_key) {
                    if *ver != svc.version {
                        svc_delta.push(Service {
                            service_id: svc.service_id.clone(),
                            version: (*ver).clone(),
                        });
                    }
                }
                svc_list.push(svc_key);
            }
        }
        ServiceClientInit {
            service_list: ClientServices {
                service_list: svc_list,
                change_count: self.change_count,
            },
            delta: svc_delta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_service_base() -> Vec<Service> {
        vec![
            Service { service_id: String::from("svca"), version: String::from("rev1") },
            Service { service_id: String::from("svcb"), version: String::from("revalha") },
        ]
    }

    #[test]
    fn test_service_change_tracker() {
        let services = make_service_base();
        let client_services = services.clone();
        let mut chglst = ServiceChangeTracker::new(services);
        let mut client_init = chglst.service_delta(client_services);
        assert_eq!(client_init.delta.len(), 0);
        assert_eq!(client_init.service_list.change_count, 0);
        assert_eq!(client_init.service_list.service_list.len(), 2);

        chglst.update_service(
            Service { service_id: String::from("svca"), version: String::from("rev2") }
        ).ok();
        let delta = chglst.change_count_delta(&mut client_init.service_list);
        assert!(delta.is_some());
        let delta = delta.unwrap();
        assert_eq!(delta.len(), 1);

        chglst.add_service(
            Service { service_id: String::from("svcc"), version: String::from("revmega") }
        );
        let delta = chglst.change_count_delta(&mut client_init.service_list);
        assert!(delta.is_some());
        let delta = delta.unwrap();
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].version, String::from("revmega"));
        assert_eq!(client_init.service_list.change_count, 2);
        assert_eq!(chglst.service_list.len(), 2);
    }
}
