use anyhow::Result;
use log::{debug, info};
use std::path::PathBuf;
use crate::types::{Finding, SystemArtifacts};
use super::rules::*;

pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
        };
        
        // Load default rules
        engine.load_default_rules();
        engine
    }
    
    pub fn load_default_rules(&mut self) {
        debug!("Loading default detection rules");
        
        // High/Critical severity rules
        self.rules.push(Box::new(ServiceBinaryInUserDirRule));
        self.rules.push(Box::new(ServiceUnsignedOutsideSystemRule));
        self.rules.push(Box::new(TaskHiddenLolbasRule));
        self.rules.push(Box::new(LsaPackagesOutsideSystem32Rule));
        self.rules.push(Box::new(ProcessLolbasRule));
        self.rules.push(Box::new(IfeoDebuggerRule));
        
        // Medium severity rules
        self.rules.push(Box::new(AppInitDllsRule));
        self.rules.push(Box::new(RecentUnsignedDriverRule));
        
        // Browser security rules
        self.rules.push(Box::new(SuspiciousBrowserExtensionRule));
        self.rules.push(Box::new(CompromisedBrowserSettingsRule));
        self.rules.push(Box::new(SuspiciousDownloadRule));
        
        // Crypto theft detection rules
        self.rules.push(Box::new(CryptoWalletTheftRule));
        self.rules.push(Box::new(SuspiciousWalletAccessRule));
        self.rules.push(Box::new(CompromisedSessionRule));
        
        info!("Loaded {} detection rules", self.rules.len());
    }
    
    pub fn load_custom_rules(&mut self, _rules_path: PathBuf) -> Result<()> {
        // TODO: Implement custom rules loading from JSON/YAML
        debug!("Custom rules loading not yet implemented");
        Ok(())
    }
    
    pub fn analyze(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        info!("Running detection analysis...");
        let mut findings = Vec::new();
        
        for rule in &self.rules {
            let rule_findings = rule.evaluate(artifacts)?;
            findings.extend(rule_findings);
        }
        
        info!("Detection completed: {} findings", findings.len());
        Ok(findings)
    }
}

pub trait DetectionRule: Send + Sync {
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>>;
    fn rule_id(&self) -> &'static str;
}
