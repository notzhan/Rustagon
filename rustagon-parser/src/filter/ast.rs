#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Binary {
        field: String,
        op: BinaryOp,
        value: Value,
    },
    Exists {
        field: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOp {
    Eq,
    NotEq,
    Less,
    LessEq,
    Greater,
    GreaterEq,
    Contains,
    StartsWith,
    EndsWith,
    In,
    Pmatch,
    Glob,
}

impl BinaryOp {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::NotEq => "!=",
            Self::Less => "<",
            Self::LessEq => "<=",
            Self::Greater => ">",
            Self::GreaterEq => ">=",
            Self::Contains => "contains",
            Self::StartsWith => "startswith",
            Self::EndsWith => "endswith",
            Self::In => "in",
            Self::Pmatch => "pmatch",
            Self::Glob => "glob",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Bare(String),
    Quoted(String),
    List(Vec<Value>),
}
