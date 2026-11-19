//! BCheck definition language: lexer, parser, AST and validation.
//!
//! Grammar source: PortSwigger "BCheck definition reference" (v2-beta).
//! Structure rules enforced here:
//! - a `metadata` block is mandatory and must come first;
//! - optional `run for each` then `define` blocks follow metadata;
//! - exactly one `given ... then` statement carries the check body;
//! - conditionals only appear inside `given ... then`;
//! - `send request` is not allowed under `given response`;
//! - `send payload` requires an insertion-point `given`;
//! - `report issue` requires `severity` and `confidence`.

use std::fmt;

pub mod exec;
pub mod runner;

#[derive(Debug, Clone, PartialEq)]
pub struct Metadata {
    pub language: String,
    pub name: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertionPointKind {
    Any,
    Query,
    Header,
    Body,
    Cookie,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GivenMode {
    Response,
    Request,
    Host,
    Path,
    InsertionPoints(Vec<InsertionPointKind>),
}

impl GivenMode {
    pub fn is_insertion_point(&self) -> bool {
        matches!(self, GivenMode::InsertionPoints(_))
    }
}

/// A string value: literal text plus interpolated `{expr}` holes.
/// Literal `"..."` strings never interpolate; backtick strings do.
#[derive(Debug, Clone, PartialEq)]
pub struct Interpol {
    pub parts: Vec<Part>,
    pub interpolatable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Text(String),
    Hole(Expr),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Bare `{name}` variable reference.
    Var(String),
    /// `{base.response.url.path}` style reserved-path reference.
    Path(Vec<String>),
    /// `{name(arg, arg)}` function call; args may nest.
    Call { name: String, args: Vec<Expr> },
    /// A quoted string (its own interpolation already resolved into parts).
    Str(Interpol),
    /// Integer literal (function args such as `random_str(10)`).
    Int(i64),
    /// `null` literal (allowed in `run for each` lists).
    Null,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Bare `{expr}`.
    Hole(Expr),
    /// Quoted string.
    Str(Interpol),
    Null,
    /// Bare identifier (metadata language, severity, confidence).
    Ident(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct VarDecl {
    pub name: String,
    pub values: Vec<Value>,
    /// Source line of the declaration, for validation messages.
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModMode {
    Append,
    Replace,
    Remove,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequestMod {
    /// headers: "Name": value, ... (append adds a second header on name clash,
    /// replace overwrites or appends).
    Headers { mode: ModMode, pairs: Vec<(Value, Value)> },
    RemoveHeaders(Vec<Value>),
    /// queries: "name=value", ...
    Queries { mode: ModMode, entries: Vec<Value> },
    RemoveQueries(Vec<Value>),
    QueryString { mode: ModMode, value: Value },
    RemoveQueryString,
    Path { mode: ModMode, value: Value },
    RemovePath,
    Method { mode: ModMode, value: Value },
    RemoveMethod,
    Body { mode: ModMode, value: Value },
    RemoveBody,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IssueFields {
    /// Source line of the `report issue` statement, for validation messages.
    pub line: usize,
    pub name: Option<Value>,
    pub severity: Value,
    pub confidence: Value,
    pub remediation: Option<Value>,
    pub detail: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// `send request [called x]:` with modification entries, or a raw request
    /// string in place of the entries.
    SendRequest {
        name: Option<String>,
        raw: Option<Value>,
        mods: Vec<RequestMod>,
        /// Source line of the statement, for validation messages.
        line: usize,
    },
    /// `send payload [called x]:` with appending/replacing entries.
    SendPayload {
        name: Option<String>,
        ops: Vec<(ModMode, Value)>,
        /// Source line of the statement, for validation messages.
        line: usize,
    },
    ReportIssue { and_continue: bool, fields: IssueFields },
    /// If/else-if/else chain. The condition is `None` for the final `else`.
    If {
        arms: Vec<(Option<Condition>, Vec<Stmt>)>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    Matches(Expr, Interpol),
    Differs(Expr, Expr),
    In(Expr, Expr),
    Is(Expr, Expr),
    Interactions(InteractionKind),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InteractionKind {
    Any,
    Dns,
    Http,
    Smtp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Definition {
    pub metadata: Metadata,
    pub run_for_each: Vec<VarDecl>,
    pub define: Vec<VarDecl>,
    pub given: GivenMode,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BcheckError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for BcheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for BcheckError {}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    /// Quoted string: raw inner text (escapes still intact), interpolatable flag.
    Str { raw: String, interpolatable: bool },
    Int(i64),
    Colon,
    Comma,
    Eq,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Dot,
    Newline,
}

#[derive(Debug, Clone)]
struct Lexed {
    tok: Tok,
    line: usize,
}

fn lex(src: &str) -> Result<Vec<Lexed>, BcheckError> {
    let mut out = Vec::new();
    let mut chars = src.chars().peekable();
    let mut line = 1usize;
    while let Some(&c) = chars.peek() {
        match c {
            '\n' => {
                out.push(Lexed { tok: Tok::Newline, line });
                line += 1;
                chars.next();
            }
            '\r' | ' ' | '\t' => {
                chars.next();
            }
            '#' => {
                // comment to end of line
                while let Some(&c2) = chars.peek() {
                    if c2 == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            ':' => {
                out.push(Lexed { tok: Tok::Colon, line });
                chars.next();
            }
            ',' => {
                out.push(Lexed { tok: Tok::Comma, line });
                chars.next();
            }
            '=' => {
                out.push(Lexed { tok: Tok::Eq, line });
                chars.next();
            }
            '(' => {
                out.push(Lexed { tok: Tok::LParen, line });
                chars.next();
            }
            ')' => {
                out.push(Lexed { tok: Tok::RParen, line });
                chars.next();
            }
            '{' => {
                out.push(Lexed { tok: Tok::LBrace, line });
                chars.next();
            }
            '}' => {
                out.push(Lexed { tok: Tok::RBrace, line });
                chars.next();
            }
            '.' => {
                out.push(Lexed { tok: Tok::Dot, line });
                chars.next();
            }
            '"' | '`' => {
                let interpolatable = c == '`';
                let start_line = line;
                chars.next();
                let mut raw = String::new();
                let mut closed = false;
                while let Some(&c2) = chars.peek() {
                    if c2 == '\\' {
                        raw.push(c2);
                        chars.next();
                        if let Some(&c3) = chars.peek() {
                            raw.push(c3);
                            if c3 == '\n' {
                                line += 1;
                            }
                            chars.next();
                        }
                        continue;
                    }
                    if c2 == c {
                        chars.next();
                        closed = true;
                        break;
                    }
                    if c2 == '\n' {
                        line += 1;
                    }
                    raw.push(c2);
                    chars.next();
                }
                if !closed {
                    return Err(BcheckError {
                        line: start_line,
                        message: "unterminated string".to_string(),
                    });
                }
                out.push(Lexed {
                    tok: Tok::Str { raw, interpolatable },
                    line: start_line,
                });
            }
            _ if c.is_ascii_alphabetic() || c == '_' => {
                let mut name = String::new();
                while let Some(&c2) = chars.peek() {
                    if c2.is_ascii_alphanumeric() || c2 == '_' || c2 == '-' {
                        name.push(c2);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push(Lexed { tok: Tok::Ident(name), line });
            }
            _ if c.is_ascii_digit() => {
                let mut digits = String::new();
                while let Some(&c2) = chars.peek() {
                    if c2.is_ascii_digit() {
                        digits.push(c2);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let n: i64 = digits.parse().map_err(|_| BcheckError {
                    line,
                    message: format!("bad integer `{digits}`"),
                })?;
                out.push(Lexed { tok: Tok::Int(n), line });
            }
            other => {
                return Err(BcheckError {
                    line,
                    message: format!("unexpected character `{other}`"),
                });
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Interpolated-string parts
// ---------------------------------------------------------------------------

/// Split raw string contents into text and `{expr}` holes. Escapes are
/// resolved here (`\{` stays a literal brace; `\n`, `\s`, ... become their
/// characters in interpolatable strings).
fn parse_interpol(raw: &str, interpolatable: bool, line: usize) -> Result<Interpol, BcheckError> {
    let mut parts = Vec::new();
    let mut text = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next) => {
                    // The reference's only escape rule ("use \ to escape
                    // characters", e.g. `\{`) takes the escaped character
                    // verbatim; both string kinds do the same.
                    text.push(next);
                }
                None => text.push('\\'),
            }
            continue;
        }
        if interpolatable && c == '{' {
            // Parse a hole: tokens until the matching `}`, allowing nested
            // strings and braces (function args may contain strings with
            // their own holes).
            let hole = parse_hole(&mut chars, line)?;
            if !text.is_empty() {
                parts.push(Part::Text(std::mem::take(&mut text)));
            }
            parts.push(Part::Hole(hole));
            continue;
        }
        text.push(c);
    }
    if !text.is_empty() {
        parts.push(Part::Text(text));
    }
    Ok(Interpol { parts, interpolatable })
}

/// Parse the inside of a `{...}` hole from a character stream positioned just
/// after the opening `{`. Consumes through the closing `}`.
fn parse_hole(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    line: usize,
) -> Result<Expr, BcheckError> {
    let mut depth_toks: Vec<Lexed> = Vec::new();
    let mut depth = 1usize;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                // An escape outside a nested string is not valid expression
                // syntax; keep it as ONE token so it surfaces as a single
                // unknown variable at evaluation instead of two bogus refs.
                let escaped = chars.next().map(|n| format!("\\{n}")).unwrap_or_else(|| "\\".to_string());
                depth_toks.push(Lexed { tok: Tok::Ident(escaped), line });
            }
            '{' => {
                depth += 1;
                depth_toks.push(Lexed { tok: Tok::LBrace, line });
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return parse_hole_expr(&depth_toks, line);
                }
                depth_toks.push(Lexed { tok: Tok::RBrace, line });
            }
            '"' | '`' => {
                let interpolatable = c == '`';
                let mut raw = String::new();
                let mut closed = false;
                while let Some(c2) = chars.next() {
                    if c2 == '\\' {
                        raw.push(c2);
                        if let Some(c3) = chars.next() {
                            raw.push(c3);
                        }
                        continue;
                    }
                    if c2 == c {
                        closed = true;
                        break;
                    }
                    raw.push(c2);
                }
                if !closed {
                    return Err(BcheckError { line, message: "unterminated string in hole".into() });
                }
                depth_toks.push(Lexed { tok: Tok::Str { raw, interpolatable }, line });
            }
            ',' => depth_toks.push(Lexed { tok: Tok::Comma, line }),
            '(' => depth_toks.push(Lexed { tok: Tok::LParen, line }),
            ')' => depth_toks.push(Lexed { tok: Tok::RParen, line }),
            '.' => depth_toks.push(Lexed { tok: Tok::Dot, line }),
            c if c.is_ascii_alphanumeric() || c == '_' || c == '-' => {
                // merge with previous ident-ish token when adjacent
                let s = c.to_string();
                if let Some(last) = depth_toks.last_mut() {
                    if let Tok::Ident(prev) = &mut last.tok {
                        if !prev.ends_with('.') && prev != "\\" && is_identish(prev) {
                            prev.push_str(&s);
                            continue;
                        }
                    }
                }
                depth_toks.push(Lexed { tok: Tok::Ident(s), line });
            }
            c if c.is_whitespace() => {}
            other => {
                return Err(BcheckError {
                    line,
                    message: format!("unexpected character `{other}` in hole"),
                })
            }
        }
    }
    Err(BcheckError { line, message: "unterminated `{` hole".into() })
}

fn is_identish(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Build an Expr from the raw tokens collected inside `{...}`.
fn parse_hole_expr(toks: &[Lexed], line: usize) -> Result<Expr, BcheckError> {
    let mut p = HoleParser { toks, pos: 0, line };
    let e = p.expr()?;
    p.skip_ws();
    if p.pos != toks.len() {
        return Err(BcheckError { line, message: "trailing content in hole".into() });
    }
    Ok(e)
}

struct HoleParser<'a> {
    toks: &'a [Lexed],
    pos: usize,
    line: usize,
}

impl<'a> HoleParser<'a> {
    fn skip_ws(&mut self) {}
    fn peek(&self) -> Option<&'a Tok> {
        self.toks.get(self.pos).map(|l| &l.tok)
    }
    fn next(&mut self) -> Option<&'a Tok> {
        let t = self.toks.get(self.pos).map(|l| &l.tok);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn err(&self, msg: &str) -> BcheckError {
        BcheckError { line: self.line, message: msg.to_string() }
    }
    fn expr(&mut self) -> Result<Expr, BcheckError> {
        match self.next().cloned() {
            Some(Tok::Ident(name)) => {
                if name == "null" {
                    return Ok(Expr::Null);
                }
                let is_int_literal = name.chars().next().unwrap().is_ascii_digit()
                    || (name.len() > 1 && name.starts_with('-') && name[1..].chars().next().unwrap().is_ascii_digit());
                if let Some(n) = name.parse::<i64>().ok().filter(|_| is_int_literal) {
                    return Ok(Expr::Int(n));
                }
                match self.peek() {
                    Some(Tok::LParen) => {
                        self.next();
                        let mut args = Vec::new();
                        loop {
                            match self.peek() {
                                Some(Tok::RParen) => {
                                    self.next();
                                    break;
                                }
                                Some(_) => {
                                    args.push(self.expr()?);
                                    match self.next() {
                                        Some(Tok::Comma) => continue,
                                        Some(Tok::RParen) => break,
                                        _ => return Err(self.err("expected `,` or `)` in function args")),
                                    }
                                }
                                None => return Err(self.err("unterminated function call")),
                            }
                        }
                        Ok(Expr::Call { name, args })
                    }
                    Some(Tok::Dot) => {
                        let mut path = vec![name];
                        while matches!(self.peek(), Some(Tok::Dot)) {
                            self.next();
                            match self.next().cloned() {
                                Some(Tok::Ident(seg)) => path.push(seg),
                                _ => return Err(self.err("expected path segment after `.`")),
                            }
                        }
                        Ok(Expr::Path(path))
                    }
                    _ => Ok(Expr::Var(name)),
                }
            }
            Some(Tok::Int(n)) => Ok(Expr::Int(n)),
            Some(Tok::Str { raw, interpolatable }) => Ok(Expr::Str(parse_interpol(
                &raw,
                interpolatable,
                self.line,
            )?)),
            Some(Tok::LBrace) => {
                // nested hole value, e.g. function arg that is itself {expr}
                let e = self.expr()?;
                match self.next() {
                    Some(Tok::RBrace) => Ok(e),
                    _ => Err(self.err("expected `}`")),
                }
            }
            other => Err(self.err(&format!("unexpected token in hole: {other:?}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub fn parse(src: &str) -> Result<Definition, Vec<BcheckError>> {
    let toks = match lex(src) {
        Ok(t) => t,
        Err(e) => return Err(vec![e]),
    };
    let mut p = Parser { toks, pos: 0 };
    match p.definition() {
        Ok(d) => match validate(&d) {
            Ok(()) => Ok(d),
            Err(errs) => Err(errs),
        },
        Err(e) => Err(vec![e]),
    }
}

struct Parser {
    toks: Vec<Lexed>,
    pos: usize,
}

impl Parser {
    fn line(&self) -> usize {
        self.toks.get(self.pos).map(|l| l.line).unwrap_or(usize::MAX)
    }
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|l| &l.tok)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).map(|l| l.tok.clone());
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Some(Tok::Newline)) {
            self.pos += 1;
        }
    }
    fn err<T>(&self, msg: impl Into<String>) -> Result<T, BcheckError> {
        Err(BcheckError { line: self.line(), message: msg.into() })
    }
    fn ident(&mut self) -> Result<String, BcheckError> {
        match self.next() {
            Some(Tok::Ident(s)) => Ok(s),
            other => self.err(format!("expected identifier, got {other:?}")),
        }
    }
    fn expect_ident(&mut self, want: &str) -> Result<(), BcheckError> {
        let got = self.ident()?;
        if got == want {
            Ok(())
        } else {
            self.err(format!("expected `{want}`, got `{got}`"))
        }
    }
    fn expect(&mut self, want: Tok) -> Result<(), BcheckError> {
        let got = self.next();
        if got.as_ref() == Some(&want) {
            Ok(())
        } else {
            self.err(format!("expected {want:?}, got {got:?}"))
        }
    }
    fn definition(&mut self) -> Result<Definition, BcheckError> {
        self.skip_newlines();
        let metadata = self.metadata()?;
        self.skip_newlines();
        let mut run_for_each = Vec::new();
        let mut define = Vec::new();
        // optional `run for each:` then optional `define:` (docs place
        // run-for-each first; accept either order, enforce before given).
        loop {
            self.skip_newlines();
            match self.peek() {
                Some(Tok::Ident(s)) if s == "run" => {
                    self.next();
                    self.expect_ident("for")?;
                    self.expect_ident("each")?;
                    self.expect(Tok::Colon)?;
                    run_for_each = self.var_decls(true)?;
                }
                Some(Tok::Ident(s)) if s == "define" => {
                    self.next();
                    self.expect(Tok::Colon)?;
                    define = self.var_decls(false)?;
                }
                _ => break,
            }
        }
        self.skip_newlines();
        let (given, body) = self.given_block()?;
        self.skip_newlines();
        if self.pos < self.toks.len() {
            return self.err("unexpected content after the check body");
        }
        Ok(Definition { metadata, run_for_each, define, given, body })
    }

    fn metadata(&mut self) -> Result<Metadata, BcheckError> {
        self.expect_ident("metadata")?;
        self.expect(Tok::Colon)?;
        let mut language = None;
        let mut name = None;
        let mut description = None;
        let mut author = None;
        let mut tags = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek() {
                Some(Tok::Ident(k)) if is_metadata_key(k) => {
                    let key = k.clone();
                    self.next();
                    self.expect(Tok::Colon)?;
                    match key.as_str() {
                        "language" => language = Some(self.ident()?),
                        "name" => name = Some(self.string_value()?),
                        "description" => description = Some(self.string_value()?),
                        "author" => author = Some(self.string_value()?),
                        "tags" => {
                            loop {
                                tags.push(self.string_value()?);
                                match self.peek() {
                                    Some(Tok::Comma) => {
                                        self.next();
                                    }
                                    _ => break,
                                }
                            }
                        }
                        _ => unreachable!(),
                    }
                }
                _ => break,
            }
        }
        Ok(Metadata {
            language: language.unwrap_or_default(),
            name: name.unwrap_or_default(),
            description,
            author,
            tags,
        })
    }

    fn string_value(&mut self) -> Result<String, BcheckError> {
        match self.next() {
            Some(Tok::Str { raw, .. }) => Ok(unescape_literal(&raw)),
            other => self.err(format!("expected string, got {other:?}")),
        }
    }

    /// `name = v1, v2, ...` lines until a non-declaration line.
    fn var_decls(&mut self, multi: bool) -> Result<Vec<VarDecl>, BcheckError> {
        let mut decls = Vec::new();
        loop {
            self.skip_newlines();
            // a decl line: Ident Eq
            let is_decl = matches!(self.peek(), Some(Tok::Ident(_)))
                && matches!(self.toks.get(self.pos + 1).map(|l| &l.tok), Some(Tok::Eq));
            if !is_decl {
                break;
            }
            let decl_line = self.line();
            let name = self.ident()?;
            self.expect(Tok::Eq)?;
            self.skip_newlines();
            let mut values = vec![self.value()?];
            if multi {
                while matches!(self.peek(), Some(Tok::Comma)) {
                    self.next();
                    self.skip_newlines();
                    // trailing comma before a new decl or the next block
                    if matches!(self.peek(), Some(Tok::Ident(_)))
                        && matches!(self.toks.get(self.pos + 1).map(|l| &l.tok), Some(Tok::Eq))
                    {
                        break;
                    }
                    if let Some(Tok::Ident(s)) = self.peek() {
                        if is_block_keyword(s) {
                            break;
                        }
                    }
                    if !matches!(
                        self.peek(),
                        Some(Tok::Str { .. }) | Some(Tok::LBrace) | Some(Tok::Ident(_))
                    ) {
                        break;
                    }
                    values.push(self.value()?);
                }
            }
            decls.push(VarDecl { name, values, line: decl_line });
        }
        Ok(decls)
    }

    fn value(&mut self) -> Result<Value, BcheckError> {
        match self.next() {
            Some(Tok::Str { raw, interpolatable }) => {
                Ok(Value::Str(parse_interpol(&raw, interpolatable, self.line())?))
            }
            Some(Tok::LBrace) => {
                let e = self.expr_until_rbrace()?;
                Ok(Value::Hole(e))
            }
            Some(Tok::Ident(s)) if s == "null" => Ok(Value::Null),
            Some(Tok::Ident(s)) => Ok(Value::Ident(s)),
            other => self.err(format!("expected value, got {other:?}")),
        }
    }

    fn expr_until_rbrace(&mut self) -> Result<Expr, BcheckError> {
        let start_line = self.line();
        // collect tokens until matching RBrace at depth 0
        let mut inner: Vec<Lexed> = Vec::new();
        let mut depth = 1usize;
        loop {
            match self.next() {
                Some(Tok::LBrace) => {
                    depth += 1;
                    inner.push(Lexed { tok: Tok::LBrace, line: start_line });
                }
                Some(Tok::RBrace) => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    inner.push(Lexed { tok: Tok::RBrace, line: start_line });
                }
                Some(Tok::Newline) => {}
                Some(t) => inner.push(Lexed { tok: t, line: start_line }),
                None => {
                    return Err(BcheckError {
                        line: start_line,
                        message: "unterminated `{`".into(),
                    })
                }
            }
        }
        parse_hole_expr(&inner, start_line)
    }

    fn given_block(&mut self) -> Result<(GivenMode, Vec<Stmt>), BcheckError> {
        self.expect_ident("given")?;
        let first = self.ident()?;
        let given = match first.as_str() {
            "response" => {
                self.expect_ident("then")?;
                GivenMode::Response
            }
            "request" => {
                self.expect_ident("then")?;
                GivenMode::Request
            }
            "host" => {
                self.expect_ident("then")?;
                GivenMode::Host
            }
            "path" => {
                self.expect_ident("then")?;
                GivenMode::Path
            }
            "insertion" | "any" | "query" | "header" | "body" | "cookie" => {
                let mut kinds = Vec::new();
                let mut cur = first;
                loop {
                    match cur.as_str() {
                        "insertion" => {
                            self.expect_ident("point")?;
                            self.expect_ident("then")?;
                            if kinds.is_empty() {
                                kinds.push(InsertionPointKind::Any);
                            }
                            break;
                        }
                        "any" => kinds.push(InsertionPointKind::Any),
                        "query" => kinds.push(InsertionPointKind::Query),
                        "header" => kinds.push(InsertionPointKind::Header),
                        "body" => kinds.push(InsertionPointKind::Body),
                        "cookie" => kinds.push(InsertionPointKind::Cookie),
                        other => return self.err(format!("bad insertion point kind `{other}`")),
                    }
                    let next = self.ident()?;
                    if next == "insertion" {
                        self.expect_ident("point")?;
                        self.expect_ident("then")?;
                        break;
                    }
                    if next != "or" {
                        return self.err("expected `or` between insertion point kinds");
                    }
                    cur = self.ident()?;
                }
                GivenMode::InsertionPoints(kinds)
            }
            other => return self.err(format!("bad given mode `{other}`")),
        };
        let body = self.statements(true)?;
        Ok((given, body))
    }

    /// Parse statements until EOF (top level) or an `else`/`end if` boundary.
    fn statements(&mut self, top_level: bool) -> Result<Vec<Stmt>, BcheckError> {
        let mut out = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek() {
                None => {
                    if top_level {
                        break;
                    }
                    return self.err("unexpected end of input inside `if`");
                }
                Some(Tok::Ident(s)) => match s.as_str() {
                    "send" => out.push(self.send_stmt()?),
                    "report" => out.push(self.report_stmt()?),
                    "if" => out.push(self.if_stmt()?),
                    "else" | "end" => {
                        if top_level {
                            return self.err(format!("`{s}` without matching `if`"));
                        }
                        break;
                    }
                    other => return self.err(format!("unexpected statement `{other}`")),
                },
                Some(other) => return self.err(format!("unexpected token {other:?}")),
            }
        }
        Ok(out)
    }

    fn send_stmt(&mut self) -> Result<Stmt, BcheckError> {
        let stmt_line = self.line();
        self.expect_ident("send")?;
        let kind = self.ident()?;
        let mut name = None;
        if matches!(self.peek(), Some(Tok::Ident(s)) if s == "called") {
            self.next();
            // examples use both quoted and bare names
            name = Some(match self.next() {
                Some(Tok::Str { raw, .. }) => unescape_literal(&raw),
                Some(Tok::Ident(s)) => s,
                other => return self.err(format!("expected a request name after `called`, got {other:?}")),
            });
        }
        self.expect(Tok::Colon)?;
        match kind.as_str() {
            "request" => {
                self.skip_newlines();
                // raw request: a lone string entry. A string immediately
                // followed by `:` is a headers pair, i.e. modifications.
                if matches!(self.peek(), Some(Tok::Str { .. })) && !self.str_is_pair_key() {
                    let raw = self.value()?;
                    return Ok(Stmt::SendRequest { name, raw: Some(raw), mods: Vec::new(), line: stmt_line });
                }
                let mods = self.request_mods()?;
                Ok(Stmt::SendRequest { name, raw: None, mods, line: stmt_line })
            }
            "payload" => {
                let mut ops = Vec::new();
                loop {
                    self.skip_newlines();
                    let mode = match self.peek() {
                        Some(Tok::Ident(s)) if s == "appending" => ModMode::Append,
                        Some(Tok::Ident(s)) if s == "replacing" => ModMode::Replace,
                        _ => break,
                    };
                    self.next();
                    self.expect(Tok::Colon)?;
                    ops.push((mode, self.value()?));
                }
                if ops.is_empty() {
                    return self.err("`send payload` needs an `appending:` or `replacing:` entry");
                }
                Ok(Stmt::SendPayload { name, ops, line: stmt_line })
            }
            other => self.err(format!("expected `request` or `payload` after `send`, got `{other}`")),
        }
    }

    fn request_mods(&mut self) -> Result<Vec<RequestMod>, BcheckError> {
        let mut mods = Vec::new();
        loop {
            self.skip_newlines();
            let mode = match self.peek() {
                Some(Tok::Ident(s)) if s == "appending" => {
                    self.next();
                    Some(ModMode::Append)
                }
                Some(Tok::Ident(s)) if s == "replacing" => {
                    self.next();
                    Some(ModMode::Replace)
                }
                Some(Tok::Ident(s)) if s == "removing" => {
                    self.next();
                    Some(ModMode::Remove)
                }
                _ => None,
            };
            let what = match self.peek() {
                Some(Tok::Ident(s)) => s.clone(),
                _ => {
                    // modes only precede a mod keyword, so a non-ident here
                    // ends the block.
                    if mode.is_some() {
                        return self.err("expected a request property after the mode keyword");
                    }
                    break;
                }
            };
            // statement keywords end the modification block
            if mode.is_none()
                && matches!(what.as_str(), "send" | "report" | "if" | "else" | "end")
            {
                break;
            }
            match (mode, what.as_str()) {
                (Some(ModMode::Remove), "headers") => {
                    self.next();
                    self.expect(Tok::Colon)?;
                    mods.push(RequestMod::RemoveHeaders(self.value_list()?));
                }
                (Some(ModMode::Remove), "queries") => {
                    self.next();
                    self.expect(Tok::Colon)?;
                    mods.push(RequestMod::RemoveQueries(self.value_list()?));
                }
                (Some(ModMode::Remove), "query_string") => {
                    self.next();
                    mods.push(RequestMod::RemoveQueryString);
                }
                (Some(ModMode::Remove), "path") => {
                    self.next();
                    mods.push(RequestMod::RemovePath);
                }
                (Some(ModMode::Remove), "method") => {
                    self.next();
                    mods.push(RequestMod::RemoveMethod);
                }
                (Some(ModMode::Remove), "body") => {
                    self.next();
                    mods.push(RequestMod::RemoveBody);
                }
                (m, "headers") => {
                    self.next();
                    self.expect(Tok::Colon)?;
                    let mut pairs = Vec::new();
                    loop {
                        self.skip_newlines();
                        let k = self.value()?;
                        self.expect(Tok::Colon)?;
                        let v = self.value()?;
                        pairs.push((k, v));
                        match self.peek() {
                            Some(Tok::Comma) => {
                                self.next();
                            }
                            _ => break,
                        }
                    }
                    mods.push(RequestMod::Headers {
                        mode: m.unwrap_or(ModMode::Replace),
                        pairs,
                    });
                }
                (m, "queries") => {
                    self.next();
                    self.expect(Tok::Colon)?;
                    mods.push(RequestMod::Queries {
                        mode: m.unwrap_or(ModMode::Replace),
                        entries: self.value_list()?,
                    });
                }
                (m, "query_string") => {
                    self.next();
                    self.expect(Tok::Colon)?;
                    mods.push(RequestMod::QueryString {
                        mode: m.unwrap_or(ModMode::Replace),
                        value: self.value()?,
                    });
                }
                (m, "path") => {
                    self.next();
                    self.expect(Tok::Colon)?;
                    mods.push(RequestMod::Path {
                        mode: m.unwrap_or(ModMode::Replace),
                        value: self.value()?,
                    });
                }
                (m, "method") => {
                    self.next();
                    self.expect(Tok::Colon)?;
                    mods.push(RequestMod::Method {
                        mode: m.unwrap_or(ModMode::Replace),
                        value: self.value()?,
                    });
                }
                (m, "body") => {
                    self.next();
                    self.expect(Tok::Colon)?;
                    mods.push(RequestMod::Body {
                        mode: m.unwrap_or(ModMode::Replace),
                        value: self.value()?,
                    });
                }
                (Some(ModMode::Remove), other) => {
                    return self.err(format!("cannot remove `{other}`"));
                }
                (_, other) => return self.err(format!("unknown request property `{other}`")),
            }
        }
        Ok(mods)
    }

    fn value_list(&mut self) -> Result<Vec<Value>, BcheckError> {
        let mut vals = vec![self.value()?];
        loop {
            self.skip_newlines();
            match self.peek() {
                Some(Tok::Comma) => {
                    self.next();
                    self.skip_newlines();
                    if !matches!(
                        self.peek(),
                        Some(Tok::Str { .. }) | Some(Tok::LBrace) | Some(Tok::Ident(_))
                    ) {
                        break;
                    }
                    vals.push(self.value()?);
                }
                _ => break,
            }
        }
        Ok(vals)
    }

    fn report_stmt(&mut self) -> Result<Stmt, BcheckError> {
        let stmt_line = self.line();
        self.expect_ident("report")?;
        self.expect_ident("issue")?;
        let mut and_continue = false;
        if matches!(self.peek(), Some(Tok::Ident(s)) if s == "and") {
            self.next();
            self.expect_ident("continue")?;
            and_continue = true;
        }
        self.expect(Tok::Colon)?;
        let mut name = None;
        let mut severity = None;
        let mut confidence = None;
        let mut remediation = None;
        let mut detail = None;
        loop {
            self.skip_newlines();
            let key = match self.peek() {
                Some(Tok::Ident(s))
                    if matches!(
                        s.as_str(),
                        "name" | "severity" | "confidence" | "remediation" | "detail"
                    ) =>
                {
                    s.clone()
                }
                _ => break,
            };
            self.next();
            self.expect(Tok::Colon)?;
            let v = self.value()?;
            match key.as_str() {
                "name" => name = Some(v),
                "severity" => severity = Some(v),
                "confidence" => confidence = Some(v),
                "remediation" => remediation = Some(v),
                "detail" => detail = Some(v),
                _ => unreachable!(),
            }
        }
        let severity = severity.ok_or_else(|| BcheckError {
            line: self.line(),
            message: "`report issue` requires a severity".into(),
        })?;
        let confidence = confidence.ok_or_else(|| BcheckError {
            line: self.line(),
            message: "`report issue` requires a confidence".into(),
        })?;
        Ok(Stmt::ReportIssue {
            and_continue,
            fields: IssueFields { line: stmt_line, name, severity, confidence, remediation, detail },
        })
    }

    fn if_stmt(&mut self) -> Result<Stmt, BcheckError> {
        self.expect_ident("if")?;
        let cond = self.condition()?;
        self.expect_ident("then")?;
        let body = self.statements(false)?;
        let mut arms = vec![(Some(cond), body)];
        loop {
            self.skip_newlines();
            match self.peek() {
                Some(Tok::Ident(s)) if s == "else" => {
                    self.next();
                    match self.peek() {
                        Some(Tok::Ident(s2)) if s2 == "if" => {
                            self.next();
                            let c = self.condition()?;
                            self.expect_ident("then")?;
                            let b = self.statements(false)?;
                            arms.push((Some(c), b));
                        }
                        Some(Tok::Ident(s2)) if s2 == "then" => {
                            self.next();
                            let b = self.statements(false)?;
                            arms.push((None, b));
                        }
                        other => return self.err(format!("expected `if` or `then` after `else`, got {other:?}")),
                    }
                }
                Some(Tok::Ident(s)) if s == "end" => {
                    self.next();
                    self.expect_ident("if")?;
                    break;
                }
                other => return self.err(format!("expected `else` or `end if`, got {other:?}")),
            }
        }
        Ok(Stmt::If { arms })
    }

    /// Condition grammar: or := and (`or` and)*; and := not (`and` not)*;
    /// not := `not` `(` or `)` | atom; atom := `(` or `)` | comparison.
    fn condition(&mut self) -> Result<Condition, BcheckError> {
        self.cond_or()
    }
    fn cond_or(&mut self) -> Result<Condition, BcheckError> {
        let mut lhs = self.cond_and()?;
        loop {
            if matches!(self.peek(), Some(Tok::Ident(s)) if s == "or") {
                self.next();
                let rhs = self.cond_and()?;
                lhs = Condition::Or(Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }
    fn cond_and(&mut self) -> Result<Condition, BcheckError> {
        let mut lhs = self.cond_not()?;
        loop {
            if matches!(self.peek(), Some(Tok::Ident(s)) if s == "and") {
                self.next();
                let rhs = self.cond_not()?;
                lhs = Condition::And(Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }
    fn cond_not(&mut self) -> Result<Condition, BcheckError> {
        if matches!(self.peek(), Some(Tok::Ident(s)) if s == "not") {
            self.next();
            self.expect(Tok::LParen)?;
            let inner = self.cond_or()?;
            self.expect(Tok::RParen)?;
            return Ok(Condition::Not(Box::new(inner)));
        }
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.next();
            let inner = self.cond_or()?;
            self.expect(Tok::RParen)?;
            return Ok(inner);
        }
        self.cond_atom()
    }
    fn cond_atom(&mut self) -> Result<Condition, BcheckError> {
        // interactions keywords
        if let Some(Tok::Ident(s)) = self.peek() {
            let kind = match s.as_str() {
                "any" => Some(InteractionKind::Any),
                "dns" => Some(InteractionKind::Dns),
                "http" => Some(InteractionKind::Http),
                "smtp" => Some(InteractionKind::Smtp),
                _ => None,
            };
            if let Some(k) = kind {
                let save = self.pos;
                self.next();
                if matches!(self.peek(), Some(Tok::Ident(s2)) if s2 == "interactions") {
                    self.next();
                    return Ok(Condition::Interactions(k));
                }
                self.pos = save;
            }
        }
        let lhs = self.cond_operand()?;
        let op = self.ident()?;
        match op.as_str() {
            "matches" => {
                let re = match self.next() {
                    Some(Tok::Str { raw, interpolatable }) => {
                        parse_interpol(&raw, interpolatable, self.line())?
                    }
                    other => return self.err(format!("expected regex string after `matches`, got {other:?}")),
                };
                Ok(Condition::Matches(lhs, re))
            }
            "differs" => {
                self.expect_ident("from")?;
                let rhs = self.cond_operand()?;
                Ok(Condition::Differs(lhs, rhs))
            }
            "in" => {
                let rhs = self.cond_operand()?;
                Ok(Condition::In(lhs, rhs))
            }
            "is" => {
                let rhs = self.cond_operand()?;
                Ok(Condition::Is(lhs, rhs))
            }
            other => self.err(format!("unknown condition operator `{other}`")),
        }
    }
    fn cond_operand(&mut self) -> Result<Expr, BcheckError> {
        match self.next() {
            Some(Tok::LBrace) => self.expr_until_rbrace(),
            Some(Tok::Str { raw, interpolatable }) => Ok(Expr::Str(parse_interpol(
                &raw,
                interpolatable,
                self.line(),
            )?)),
            other => self.err(format!("expected a condition operand, got {other:?}")),
        }
    }
}

fn is_metadata_key(s: &str) -> bool {
    matches!(s, "language" | "name" | "description" | "author" | "tags")
}

fn is_block_keyword(s: &str) -> bool {
    matches!(
        s,
        "metadata" | "run" | "define" | "given" | "if" | "else" | "end" | "send" | "report"
    )
}

impl Parser {
    /// True when the string at the cursor is immediately followed by `:`
    /// (a headers pair key rather than a raw request body).
    fn str_is_pair_key(&self) -> bool {
        let mut i = self.pos + 1;
        while let Some(l) = self.toks.get(i) {
            if l.tok != Tok::Newline {
                return l.tok == Tok::Colon;
            }
            i += 1;
        }
        false
    }
}

/// Resolve `\x` escapes in a literal (non-interpolating) context: the escaped
/// character is taken verbatim.
fn unescape_literal(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(n) => out.push(n),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const RESERVED_VARS: &[&str] = &[
    "base",
    "latest",
    "request",
    "response",
    "user_agent",
    "insertion_point_base_value",
];
const FUNCTIONS: &[&str] = &[
    "random_str",
    "regex_replace",
    "to_lower",
    "to_upper",
    "base64_encode",
    "base64_decode",
    "generate_collaborator_address",
    "sha1",
    "sha256",
    "md5",
];
const SEVERITIES: &[&str] = &["info", "low", "medium", "high"];
const CONFIDENCES: &[&str] = &["certain", "firm", "tentative"];

/// The text of a Value written as one literal: a bare ident or a quoted
/// string with no holes (interpolated values are resolved at run time and
/// cannot be validated here).
fn literal_text(v: &Value) -> Option<String> {
    match v {
        Value::Ident(s) => Some(s.clone()),
        Value::Str(i) if i.parts.len() == 1 => match &i.parts[0] {
            Part::Text(t) => Some(t.clone()),
            _ => None,
        },
        _ => None,
    }
}

pub fn validate(d: &Definition) -> Result<(), Vec<BcheckError>> {
    let mut errs = Vec::new();
    if d.metadata.language != "v2-beta" {
        errs.push(BcheckError {
            line: 1,
            message: format!(
                "metadata language must be `v2-beta`, got `{}`",
                d.metadata.language
            ),
        });
    }
    if d.metadata.name.is_empty() {
        errs.push(BcheckError { line: 1, message: "metadata requires a name".into() });
    }
    for decl in d.run_for_each.iter().chain(d.define.iter()) {
        if RESERVED_VARS.contains(&decl.name.as_str()) || FUNCTIONS.contains(&decl.name.as_str()) {
            errs.push(BcheckError {
                line: decl.line,
                message: format!("variable name `{}` is reserved", decl.name),
            });
        }
    }
    // statement-level rules
    fn check_stmts(stmts: &[Stmt], given: &GivenMode, errs: &mut Vec<BcheckError>) {
        for s in stmts {
            match s {
                Stmt::SendRequest { line, .. } => {
                    if matches!(given, GivenMode::Response) {
                        errs.push(BcheckError {
                            line: *line,
                            message: "`send request` is not allowed under `given response`".into(),
                        });
                    }
                }
                Stmt::SendPayload { line, .. } => {
                    if !given.is_insertion_point() {
                        errs.push(BcheckError {
                            line: *line,
                            message: "`send payload` requires an insertion-point check".into(),
                        });
                    }
                }
                Stmt::ReportIssue { fields, .. } => {
                    // bare and single-literal quoted spellings both checked
                    if let Some(sev) = literal_text(&fields.severity) {
                        if !SEVERITIES.contains(&sev.as_str()) {
                            errs.push(BcheckError {
                                line: fields.line,
                                message: format!("bad severity `{sev}`"),
                            });
                        }
                    }
                    if let Some(cf) = literal_text(&fields.confidence) {
                        if !CONFIDENCES.contains(&cf.as_str()) {
                            errs.push(BcheckError {
                                line: fields.line,
                                message: format!("bad confidence `{cf}`"),
                            });
                        }
                    }
                }
                Stmt::If { arms } => {
                    for (_, body) in arms {
                        check_stmts(body, given, errs);
                    }
                }
            }
        }
    }
    check_stmts(&d.body, &d.given, &mut errs);
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = include_str!("../../tests/fixtures/bchecks/host.bcheck");
    const PATH: &str = include_str!("../../tests/fixtures/bchecks/path.bcheck");
    const PASSIVE: &str = include_str!("../../tests/fixtures/bchecks/passive.bcheck");
    const INSERTION: &str = include_str!("../../tests/fixtures/bchecks/insertion-point.bcheck");
    const COLLABORATOR: &str = include_str!("../../tests/fixtures/bchecks/collaborator.bcheck");
    const LOG4SHELL: &str = include_str!("../../tests/fixtures/bchecks/log4shell.bcheck");
    const SSPP: &str = include_str!("../../tests/fixtures/bchecks/sspp.bcheck");

    fn ok(src: &str) -> Definition {
        match parse(src) {
            Ok(d) => d,
            Err(errs) => panic!("parse failed: {errs:?}"),
        }
    }

    #[test]
    fn burp_example_host_check_parses() {
        let d = ok(HOST);
        assert_eq!(d.metadata.language, "v2-beta");
        assert_eq!(d.metadata.name, "Host-level");
        assert_eq!(d.given, GivenMode::Host);
        assert_eq!(d.run_for_each.len(), 1);
        assert_eq!(d.run_for_each[0].name, "potential_path");
        assert_eq!(d.run_for_each[0].values.len(), 2);
        // body: send request called check + if
        assert_eq!(d.body.len(), 2);
        match &d.body[0] {
            Stmt::SendRequest { name, mods, raw, .. } => {
                assert_eq!(name.as_deref(), Some("check"));
                assert!(raw.is_none());
                assert_eq!(mods.len(), 2);
            }
            other => panic!("expected send request, got {other:?}"),
        }
        match &d.body[1] {
            Stmt::If { arms } => {
                assert_eq!(arms.len(), 1);
                match &arms[0].0 {
                    Some(Condition::In(Expr::Str(_), Expr::Path(p))) => {
                        assert_eq!(p, &vec!["check".to_string(), "response".to_string(), "body".to_string()]);
                    }
                    other => panic!("bad condition {other:?}"),
                }
                match &arms[0].1[0] {
                    Stmt::ReportIssue { and_continue, fields } => {
                        assert!(!and_continue);
                        assert_eq!(fields.severity, Value::Ident("info".into()));
                        assert_eq!(fields.confidence, Value::Ident("certain".into()));
                    }
                    other => panic!("expected report issue, got {other:?}"),
                }
            }
            other => panic!("expected if, got {other:?}"),
        }
    }

    #[test]
    fn burp_example_path_check_parses_nested_ifs_and_functions() {
        let d = ok(PATH);
        assert_eq!(d.given, GivenMode::Path);
        assert_eq!(d.run_for_each[0].values.len(), 4);
        // outer if not(...) then send + if ... end if
        let Stmt::If { arms } = &d.body[0] else { panic!("expected if") };
        assert_eq!(arms.len(), 1);
        match &arms[0].0 {
            Some(Condition::Not(inner)) => match inner.as_ref() {
                Condition::Is(Expr::Path(p), Expr::Str(_)) => {
                    assert_eq!(p.last().map(String::as_str), Some("status_code"));
                }
                other => panic!("bad inner {other:?}"),
            },
            other => panic!("bad condition {other:?}"),
        }
        // the send request uses regex_replace with an interpolatable `$1{extension}`
        let Stmt::SendRequest { mods, .. } = &arms[0].1[0] else { panic!("expected send") };
        let RequestMod::Path { value: Value::Hole(Expr::Call { name, args }), .. } = &mods[0] else {
            panic!("expected replacing path regex_replace, got {mods:?}");
        };
        assert_eq!(name, "regex_replace");
        assert_eq!(args.len(), 3);
        let Expr::Str(tpl) = &args[2] else { panic!("expected string arg") };
        assert!(tpl.parts.iter().any(|p| matches!(p, Part::Hole(Expr::Var(v)) if v == "extension")));
        // `report issue and continue` at the innermost level
        let Stmt::If { arms: a2 } = &arms[0].1[1] else { panic!("expected inner if") };
        let Stmt::If { arms: a3 } = &a2[0].1[1] else { panic!("expected third if") };
        let Stmt::ReportIssue { and_continue, .. } = &a3[0].1[0] else { panic!("expected report") };
        assert!(and_continue);
    }

    #[test]
    fn burp_example_passive_check_parses() {
        let d = ok(PASSIVE);
        assert_eq!(d.given, GivenMode::Response);
        assert_eq!(d.metadata.tags, vec!["passive".to_string()]);
        let Stmt::If { arms } = &d.body[0] else { panic!("expected if") };
        match &arms[0].0 {
            Some(Condition::Matches(Expr::Path(p), re)) => {
                assert_eq!(p, &vec!["latest".to_string(), "response".to_string()]);
                assert!(matches!(&re.parts[0], Part::Text(t) if t == "AKIA[0-9A-Z]{16}"));
            }
            other => panic!("bad condition {other:?}"),
        }
    }

    #[test]
    fn burp_example_insertion_point_check_parses() {
        let d = ok(INSERTION);
        assert!(d.given.is_insertion_point());
        assert_eq!(d.define.len(), 2);
        // the literal "{{1337*1337}}" stays literal text in a "" string
        match &d.define[0].values[0] {
            Value::Str(s) => {
                assert!(!s.interpolatable);
                assert!(matches!(&s.parts[0], Part::Text(t) if t == "{{1337*1337}}"));
            }
            other => panic!("bad define value {other:?}"),
        }
        // send payload appending: {calculation}
        let Stmt::If { arms } = &d.body[0] else { panic!("expected if") };
        let Stmt::SendPayload { ops, .. } = &arms[0].1[0] else { panic!("expected send payload") };
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].0, ModMode::Append);
    }

    #[test]
    fn burp_example_collaborator_check_parses() {
        let d = ok(COLLABORATOR);
        assert_eq!(d.given, GivenMode::Request);
        let Stmt::SendRequest { mods, .. } = &d.body[0] else { panic!("expected send") };
        let RequestMod::Headers { pairs, .. } = &mods[0] else { panic!("expected headers") };
        // "Referer": {generate_collaborator_address()}
        assert!(matches!(&pairs[0].1, Value::Hole(Expr::Call { name, .. }) if name == "generate_collaborator_address"));
        let Stmt::If { arms } = &d.body[1] else { panic!("expected if") };
        assert!(matches!(arms[0].0, Some(Condition::Interactions(InteractionKind::Http))));
    }

    #[test]
    fn burp_example_log4shell_check_parses() {
        let d = ok(LOG4SHELL);
        assert_eq!(d.define.len(), 4);
        // escaped `\{` inside an interpolatable string stays a literal brace
        match &d.define[0].values[0] {
            Value::Str(s) => {
                let text: String = s.parts.iter().filter_map(|p| match p {
                    Part::Text(t) => Some(t.as_str()),
                    _ => None,
                }).collect();
                assert!(text.contains("${jndi:ldap://"), "got {text:?}");
                assert!(s.parts.iter().any(|p| matches!(p, Part::Hole(Expr::Call { name, .. }) if name == "generate_collaborator_address")));
            }
            other => panic!("bad define value {other:?}"),
        }
        // if dns interactions then send ... if not(dns interactions) then report
        let Stmt::If { arms } = &d.body[1] else { panic!("expected if") };
        assert!(matches!(arms[0].0, Some(Condition::Interactions(InteractionKind::Dns))));
        let Stmt::If { arms: inner } = &arms[0].1[1] else { panic!("expected inner if") };
        assert!(matches!(inner[0].0, Some(Condition::Not(_))));
    }

    #[test]
    fn burp_example_sspp_check_parses() {
        let d = ok(SSPP);
        assert_eq!(d.given, GivenMode::Request);
        // `,"__proto__":\{"status\":510\}\}` keeps literal braces and quotes
        match &d.define[0].values[0] {
            Value::Str(s) => {
                let text: String = s.parts.iter().filter_map(|p| match p {
                    Part::Text(t) => Some(t.as_str()),
                    _ => None,
                }).collect();
                assert_eq!(text, ",\"__proto__\":{\"status\":510}}");
            }
            other => panic!("bad define value {other:?}"),
        }
        // three nested ifs, regex_replace over {base.request.body}
        let Stmt::If { arms } = &d.body[0] else { panic!("expected if") };
        assert!(matches!(&arms[0].0, Some(Condition::Matches(Expr::Path(p), _)) if p.len() == 3));
        let Stmt::SendRequest { name, mods, .. } = &arms[0].1[0] else { panic!("expected send") };
        assert_eq!(name.as_deref(), Some("inject_sspp"));
        assert!(matches!(&mods[1], RequestMod::Body { value: Value::Hole(Expr::Call { name, .. }), .. } if name == "regex_replace"));
    }

    #[test]
    fn condition_precedence_and_parens() {
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ngiven response then\n if {latest.response} matches \"a\" or {latest.response} matches \"b\" and {latest.response} matches \"c\" then\n  report issue:\n   severity: info\n   confidence: certain\n end if\n";
        let d = ok(src);
        let Stmt::If { arms } = &d.body[0] else { panic!() };
        // or binds looser than and
        assert!(matches!(arms[0].0, Some(Condition::Or(_, _))));
        let Some(Condition::Or(_, rhs)) = &arms[0].0 else { panic!() };
        assert!(matches!(rhs.as_ref(), Condition::And(_, _)));

        let src2 = "metadata:\n language: v2-beta\n name: \"x\"\ngiven response then\n if ({latest.response} matches \"a\" or {latest.response} matches \"b\") and {latest.response} matches \"c\" then\n  report issue:\n   severity: info\n   confidence: certain\n end if\n";
        let d2 = ok(src2);
        let Stmt::If { arms } = &d2.body[0] else { panic!() };
        assert!(matches!(arms[0].0, Some(Condition::And(_, _))));
    }

    #[test]
    fn combined_insertion_point_kinds() {
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ngiven query or body insertion point then\n report issue:\n  severity: info\n  confidence: tentative\n";
        let d = ok(src);
        assert_eq!(
            d.given,
            GivenMode::InsertionPoints(vec![InsertionPointKind::Query, InsertionPointKind::Body])
        );
        // bare `given insertion point` defaults to any
        let src2 = "metadata:\n language: v2-beta\n name: \"x\"\ngiven insertion point then\n report issue:\n  severity: info\n  confidence: tentative\n";
        assert_eq!(ok(src2).given, GivenMode::InsertionPoints(vec![InsertionPointKind::Any]));
    }

    #[test]
    fn validation_reports_real_lines_and_quoted_enums() {
        // quoted severity/confidence spellings are validated like bare ones
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ngiven host then\n report issue:\n  severity: \"hihg\"\n  confidence: certain\n";
        let errs = parse(src).unwrap_err();
        assert!(errs.iter().any(|e| e.message.contains("bad severity") && e.line == 5), "{errs:?}");
        // a bad confidence on its own line reports that line
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ngiven host then\n report issue:\n  severity: low\n  confidence: \"sure\"\n";
        let errs = parse(src).unwrap_err();
        assert!(errs.iter().any(|e| e.message.contains("bad confidence") && e.line == 5), "{errs:?}");
        // send payload under the wrong given reports the statement's line
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ngiven host then\n send payload:\n  appending: \"x\"\n";
        let errs = parse(src).unwrap_err();
        assert!(errs.iter().any(|e| e.message.contains("insertion-point") && e.line == 5), "{errs:?}");
        // reserved variable names report the declaration's line
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ndefine:\n base64_encode = \"x\"\ngiven host then\n report issue:\n  severity: low\n  confidence: firm\n";
        let errs = parse(src).unwrap_err();
        assert!(errs.iter().any(|e| e.message.contains("reserved") && e.line == 5), "{errs:?}");
    }

    #[test]
    fn negative_integers_and_verbatim_escapes() {
        // a negative integer in a hole is an Int, not a variable reference
        let i = parse_interpol("{random_str(-10)}", true, 1).unwrap();
        match &i.parts[0] {
            Part::Hole(Expr::Call { args, .. }) => assert_eq!(args[0], Expr::Int(-10)),
            other => panic!("expected a call, got {other:?}"),
        }
        // escapes take the escaped character verbatim in both string kinds:
        // `\n` stays backslash-n's tail `n`, as the reference's `\{` rule reads
        let i = parse_interpol("a\\nb", true, 1).unwrap();
        assert!(matches!(&i.parts[0], Part::Text(t) if t == "anb"));
    }

    #[test]
    fn validation_rejects_bad_definitions() {
        // wrong language
        let src = "metadata:\n language: v1\n name: \"x\"\ngiven host then\n report issue:\n  severity: info\n  confidence: certain\n";
        assert!(parse(src).is_err());
        // missing name
        let src = "metadata:\n language: v2-beta\ngiven host then\n report issue:\n  severity: info\n  confidence: certain\n";
        assert!(parse(src).is_err());
        // missing severity
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ngiven host then\n report issue:\n  confidence: certain\n";
        assert!(parse(src).is_err());
        // send payload under given host
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ngiven host then\n send payload:\n  appending: \"x\"\n";
        assert!(parse(src).is_err());
        // send request under given response
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ngiven response then\n send request:\n  method: \"GET\"\n";
        assert!(parse(src).is_err());
        // bad severity value
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ngiven host then\n report issue:\n  severity: catastrophic\n  confidence: certain\n";
        assert!(parse(src).is_err());
        // reserved variable name
        let src = "metadata:\n language: v2-beta\n name: \"x\"\ndefine:\n latest = \"y\"\ngiven host then\n report issue:\n  severity: info\n  confidence: certain\n";
        assert!(parse(src).is_err());
    }

    #[test]
    fn syntax_errors_are_reported() {
        // unterminated string
        assert!(parse("metadata:\n language: v2-beta\n name: \"x").is_err());
        // unterminated hole
        assert!(parse("metadata:\n language: v2-beta\n name: \"x\"\ngiven host then\n send request:\n  path: {base.request.url").is_err());
        // trailing content
        assert!(parse("metadata:\n language: v2-beta\n name: \"x\"\ngiven host then\n report issue:\n  severity: info\n  confidence: certain\ngiven host then\n report issue:\n  severity: info\n  confidence: certain\n").is_err());
        // else without if
        assert!(parse("metadata:\n language: v2-beta\n name: \"x\"\ngiven host then\n else then\n report issue:\n  severity: info\n  confidence: certain\n").is_err());
    }
}
