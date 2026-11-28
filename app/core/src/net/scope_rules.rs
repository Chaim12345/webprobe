// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

/// Target scope entry. Include=false excludes a matching location.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeRule {
    pub enabled: bool,
    pub include: bool,
    pub pattern: String,
    pub is_regex: bool,
}

impl ScopeRule {
    pub fn include(pattern: impl Into<String>, is_regex: bool) -> Self {
        Self {
            enabled: true,
            include: true,
            pattern: pattern.into(),
            is_regex,
        }
    }
}

/// One session-handling rule. The local implementation supports the original's
/// core actions: set a header, reuse a captured cookie, or run a macro first.
#[derive(Clone)]
pub struct SessionRule {
    pub enabled: bool,
    pub name: String,
    /// One of [`SESSION_ACTIONS`].
    pub action: String,
    pub host_match: String,
    /// The action's argument: `Name: value`, `name=value`, a cookie name, a
    /// macro name, or an extension's session handling action.
    pub value: String,
    /// Tools the rule applies to (Burp's "Tools scope").
    pub tools: Vec<String>,
    /// "check session": the expression looked for in the validation response.
    pub check: String,
    /// "check session": true when finding the expression means the session
    /// is invalid ("Please log in"), false when it means valid.
    pub check_invalid_on_match: bool,
}

/// Burp's default tool scope for a new session rule: everything except the
/// Proxy (which Burp marks "use with caution").
pub const SESSION_DEFAULT_TOOLS: [&str; 5] =
    ["Target", "Scanner", "Repeater", "Intruder", "Sequencer"];

impl SessionRule {
    pub fn new() -> Self {
        Self {
            enabled: true,
            name: "New session rule".into(),
            action: "set header".into(),
            host_match: String::new(),
            value: String::new(),
            tools: SESSION_DEFAULT_TOOLS
                .iter()
                .map(|t| t.to_string())
                .collect(),
            check: String::new(),
            check_invalid_on_match: true,
        }
    }
}

impl Default for SessionRule {
    fn default() -> Self {
        Self::new()
    }
}

/// A reusable raw request executed by session rules and from the Sessions tab.
#[derive(Clone)]
pub struct Macro {
    pub name: String,
    pub request: String,
}

/// The scope list with its patterns compiled once, when the list is edited.
///
/// Readers take an `Arc` clone (`Shared.scope`) and match without holding the
/// lock; nothing recompiles a regex per URL.
#[derive(Clone, Default)]
pub struct ScopeRules {
    rules: Vec<ScopeRule>,
    compiled: Vec<CompiledScopeRule>,
}

#[derive(Clone)]
struct CompiledScopeRule {
    include: bool,
    matcher: PatternMatcher,
}

#[derive(Clone)]
enum PatternMatcher {
    Literal(String),
    Regex(regex::Regex),
}

impl PatternMatcher {
    fn new(pattern: &str, is_regex: bool) -> Option<Self> {
        if is_regex {
            regex::Regex::new(pattern).ok().map(Self::Regex)
        } else {
            Some(Self::Literal(pattern.to_string()))
        }
    }

    fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Literal(needle) => text.contains(needle.as_str()),
            Self::Regex(re) => re.is_match(text),
        }
    }
}

impl ScopeRules {
    /// Compile every enabled, non-blank rule; the rest select nothing.
    pub fn new(rules: Vec<ScopeRule>) -> Self {
        let compiled = rules
            .iter()
            .filter(|r| r.enabled && !r.pattern.trim().is_empty())
            .filter_map(|r| {
                PatternMatcher::new(&r.pattern, r.is_regex).map(|matcher| CompiledScopeRule {
                    include: r.include,
                    matcher,
                })
            })
            .collect();
        Self { rules, compiled }
    }

    pub fn rules(&self) -> &[ScopeRule] {
        &self.rules
    }

    pub fn into_rules(self) -> Vec<ScopeRule> {
        self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn push(&mut self, rule: ScopeRule) {
        if rule.enabled
            && !rule.pattern.trim().is_empty()
            && let Some(matcher) = PatternMatcher::new(&rule.pattern, rule.is_regex)
        {
            self.compiled.push(CompiledScopeRule {
                include: rule.include,
                matcher,
            });
        }
        self.rules.push(rule);
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&ScopeRule) -> bool) {
        let rules = std::mem::take(&mut self.rules);
        *self = Self::new(rules.into_iter().filter(|r| keep(r)).collect());
    }

    /// True when the URL is in target scope: no include entries means
    /// everything is in scope, and an exclude entry always wins.
    pub fn in_scope(&self, url: &str) -> bool {
        if self
            .compiled
            .iter()
            .any(|r| !r.include && r.matcher.is_match(url))
        {
            return false;
        }
        let mut includes = self.compiled.iter().filter(|r| r.include);
        let Some(first) = includes.next() else {
            return true;
        };
        first.matcher.is_match(url) || includes.any(|r| r.matcher.is_match(url))
    }
}

impl std::ops::Deref for ScopeRules {
    type Target = [ScopeRule];

    fn deref(&self) -> &Self::Target {
        &self.rules
    }
}

impl From<Vec<ScopeRule>> for ScopeRules {
    fn from(rules: Vec<ScopeRule>) -> Self {
        Self::new(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_scope_keeps_the_include_exclude_semantics() {
        let rules = ScopeRules::new(vec![
            ScopeRule::include("example\\.com", true),
            ScopeRule {
                enabled: true,
                include: false,
                pattern: "/logout".into(),
                is_regex: false,
            },
            ScopeRule {
                enabled: false,
                include: true,
                pattern: "never".into(),
                is_regex: false,
            },
            ScopeRule {
                enabled: true,
                include: true,
                pattern: "   ".into(),
                is_regex: true,
            },
        ]);
        assert!(rules.in_scope("https://example.com/a"));
        assert!(!rules.in_scope("https://example.com/logout"));
        assert!(!rules.in_scope("https://other.test/a"));
        assert!(ScopeRules::default().in_scope("anything"));
    }

    #[test]
    fn push_and_retain_recompile() {
        let mut rules = ScopeRules::default();
        rules.push(ScopeRule::include("^https://a\\.test/", true));
        assert!(rules.in_scope("https://a.test/x"));
        assert!(!rules.in_scope("https://b.test/x"));
        rules.retain(|r| r.pattern.contains("b.test"));
        assert!(rules.in_scope("https://b.test/x"));
        assert!(
            rules.in_scope("https://a.test/x"),
            "no include, all in scope"
        );
    }
}
