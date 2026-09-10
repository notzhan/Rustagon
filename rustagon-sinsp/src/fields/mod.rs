mod container;
mod evt;
mod fd;
mod proc;
mod user;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldClass {
    Evt,
    Proc,
    Fd,
    User,
    Container,
}

impl FieldClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evt => "evt",
            Self::Proc => "proc",
            Self::Fd => "fd",
            Self::User => "user",
            Self::Container => "container",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldInfo {
    pub name: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub field_class: FieldClass,
}

pub(crate) fn registry() -> Vec<FieldInfo> {
    let mut fields = Vec::with_capacity(
        evt::FIELDS.len()
            + proc::FIELDS.len()
            + fd::FIELDS.len()
            + user::FIELDS.len()
            + container::FIELDS.len(),
    );
    fields.extend_from_slice(evt::FIELDS);
    fields.extend_from_slice(proc::FIELDS);
    fields.extend_from_slice(fd::FIELDS);
    fields.extend_from_slice(user::FIELDS);
    fields.extend_from_slice(container::FIELDS);
    fields.sort_unstable_by_key(|field| field.name);
    fields
}

macro_rules! fields {
    ($class:ident; $(($name:literal, $display:literal)),+ $(,)?) => {
        &[
            $(
                super::FieldInfo {
                    name: $name,
                    display_name: $display,
                    description: "",
                    field_class: super::FieldClass::$class,
                },
            )+
        ]
    };
}

pub(crate) use fields;
