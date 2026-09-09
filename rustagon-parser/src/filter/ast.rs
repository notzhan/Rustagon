#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Identifier(String),
    Binary {
        left: Operand,
        op: BinaryOp,
        value: Value,
    },
    Exists {
        left: Operand,
    },
}

impl Expr {
    pub fn binary(left: Operand, op: BinaryOp, value: Value) -> Self {
        Self::Binary { left, op, value }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    Field(String),
    Transformer { name: String, args: Vec<Operand> },
    List(Vec<Operand>),
    Literal(Value),
}

impl Operand {
    pub fn field(name: impl Into<String>) -> Self {
        Self::Field(name.into())
    }

    pub fn transformer(name: impl Into<String>, args: Vec<Self>) -> Self {
        Self::Transformer {
            name: name.into(),
            args,
        }
    }
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
    IContains,
    StartsWith,
    EndsWith,
    In,
    Intersects,
    Pmatch,
    Glob,
}

impl BinaryOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::NotEq => "!=",
            Self::Less => "<",
            Self::LessEq => "<=",
            Self::Greater => ">",
            Self::GreaterEq => ">=",
            Self::Contains => "contains",
            Self::IContains => "icontains",
            Self::StartsWith => "startswith",
            Self::EndsWith => "endswith",
            Self::In => "in",
            Self::Intersects => "intersects",
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
