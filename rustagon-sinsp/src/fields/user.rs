use super::{fields, FieldInfo};

pub(super) const FIELDS: &[FieldInfo] = fields!(User;
    ("user.homedir", "Home Directory"),
    ("user.loginname", "Login User Name"),
    ("user.loginuid", "Login User ID"),
    ("user.name", "User Name"),
    ("user.shell", "Shell"),
    ("user.uid", "User ID"),
);
