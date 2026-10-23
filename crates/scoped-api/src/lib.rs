//! Typed public D-Bus protocol for scoped.

pub const BUS_NAME: &str = "org.decoupling.scoped1";
pub const OBJECT_PATH: &str = "/org/decoupling/scoped1";
pub const INTERFACE_NAME: &str = "org.decoupling.scoped1.Manager";

#[zbus::proxy(
    interface = "org.decoupling.scoped1.Manager",
    default_service = "org.decoupling.scoped1",
    default_path = "/org/decoupling/scoped1"
)]
pub trait Manager {
    fn create(&self, id: &str) -> zbus::Result<()>;

    #[zbus(name = "Move")]
    fn move_pid(&self, pid: u32, id: &str, target_id: &str) -> zbus::Result<()>;

    fn scope_of(&self, pid: u32) -> zbus::Result<String>;
    fn list(&self, prefix: &str) -> zbus::Result<Vec<String>>;
    fn target_exists(&self, id: &str, target_id: &str) -> zbus::Result<bool>;
    fn scope_populated(&self, id: &str) -> zbus::Result<bool>;
    fn terminate_target(&self, id: &str, target_id: &str) -> zbus::Result<()>;
    fn kill_target(&self, id: &str, target_id: &str) -> zbus::Result<()>;
    fn terminate_scope(&self, id: &str) -> zbus::Result<()>;
    fn kill_scope(&self, id: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn target_gone(&self, id: &str, target_id: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn scope_empty(&self, id: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn scope_removed(&self, id: &str) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_names_are_stable() {
        assert_eq!(BUS_NAME, "org.decoupling.scoped1");
        assert_eq!(OBJECT_PATH, "/org/decoupling/scoped1");
        assert_eq!(INTERFACE_NAME, "org.decoupling.scoped1.Manager");
    }
}
