// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"fmt"

	"github.com/appsentinels/coraza/v3/internal/corazawaf"
	"github.com/appsentinels/coraza/v3/internal/seclang"
	"github.com/appsentinels/coraza/v3/types"
)

// WAF instance is used to store configurations and rules
// Every web application should have a different WAF instance,
// but you can share an instance if you are ok with sharing
// configurations, rules and logging.
// Transactions and SecLang parser requires a WAF instance
// You can use as many WAF instances as you want, and they are
// concurrent safe
type WAF interface {
	// NewTransaction Creates a new initialized transaction for this WAF instance
	NewTransaction() types.Transaction
	NewTransactionWithID(id string) types.Transaction
	// MJ Change
	WafGetRulesInfo(flagName string) interface{}
	WafUpdateRuleFlags(flagName string, flagValue interface{}) bool

	// Sachin Changes for enabling debug logging without reloading rules again
	// [[
	SetTransactionDebugLevel(debugLevel int)
	// ]]
}

// NewWAF creates a new WAF instance with the provided configuration.
func NewWAF(config WAFConfig) (WAF, error) {
	c := config.(*wafConfig)

	waf := corazawaf.NewWAF()

	if c.debugLogger != nil {
		waf.Logger = c.debugLogger
	}

	parser := seclang.NewParser(waf)

	if c.fsRoot != nil {
		parser.SetRoot(c.fsRoot)
	}

	for _, r := range c.rules {
		switch {
		case r.rule != nil:
			if err := waf.Rules.Add(r.rule); err != nil {
				return nil, fmt.Errorf("invalid WAF config from rule: %w", err)
			}
		case r.str != "":
			if err := parser.FromString(r.str); err != nil {
				return nil, fmt.Errorf("invalid WAF config from string: %w", err)
			}
		case r.file != "":
			if err := parser.FromFile(r.file); err != nil {
				return nil, fmt.Errorf("invalid WAF config from file: %w", err)
			}
		}
	}

	if a := c.auditLog; a != nil {
		if a.relevantOnly {
			waf.AuditEngine = types.AuditEngineRelevantOnly
		} else {
			waf.AuditEngine = types.AuditEngineOn
		}

		waf.AuditLogParts = a.parts

		if a.writer != nil {
			waf.SetAuditLogWriter(a.writer)
		}
	}

	if err := waf.InitAuditLogWriter(); err != nil {
		return nil, fmt.Errorf("invalid WAF config from audit log: %w", err)
	}

	if c.requestBodyAccess {
		waf.RequestBodyAccess = true
	}

	if c.requestBodyLimit != nil {
		waf.RequestBodyLimit = int64(*c.requestBodyLimit)
	}

	if c.requestBodyInMemoryLimit != nil {
		waf.SetRequestBodyInMemoryLimit(int64(*c.requestBodyInMemoryLimit))
	}

	if c.responseBodyAccess {
		waf.ResponseBodyAccess = true
	}

	if c.responseBodyLimit != nil {
		waf.ResponseBodyLimit = int64(*c.responseBodyLimit)
	}

	if c.responseBodyMimeTypes != nil {
		waf.ResponseBodyMimeTypes = c.responseBodyMimeTypes
	}

	if c.errorCallback != nil {
		waf.ErrorLogCb = c.errorCallback
	}

	if err := waf.Validate(); err != nil {
		return nil, err
	}

	return wafWrapper{waf: waf}, nil
}

type wafWrapper struct {
	waf *corazawaf.WAF
}

// NewTransaction implements the same method on WAF.
func (w wafWrapper) NewTransaction() types.Transaction {
	return w.waf.NewTransaction()
}

// NewTransactionWithID implements the same method on WAF.
func (w wafWrapper) NewTransactionWithID(id string) types.Transaction {
	return w.waf.NewTransactionWithID(id)
}

//MJ changes [ --
func (w wafWrapper) WafGetRulesInfo(flagName string) interface{} {
	return corazawaf.GetRuleTimingsRecord() //only 1 supported as of now
}

// Sachin Changes for enabling debug logging without reloading rules again
// [[
func (w wafWrapper) SetTransactionDebugLevel(debugLevel int) {
	w.waf.SetTransactionDebugLevel(debugLevel)
}

// ]]

func (w wafWrapper) WafUpdateRuleFlags(flagName string, flagValue interface{}) bool {
	ret_val := false
	switch flagName {
	case "printtransformationrule":
		if val, ok := flagValue.(bool); ok {
			corazawaf.UpdatePrintTransformationRules(val)
			ret_val = true
		}
	case "recordruletimings":
		if val, ok := flagValue.(bool); ok {
			corazawaf.UpdateRecordRuleTimings(val)
			ret_val = true
		}
	case "recordruletimingsclear":
		corazawaf.ClearRuleTimingsRecord()
		ret_val = true
	case "hideflag":
		if val, ok := flagValue.(bool); ok {
			fmt.Println("WafUpdateRuleFlags: updating hideflag: ", w.waf.HideValues, val)
			w.waf.HideValues = val //a direct write from wrapper to internal object -- should be ok
			ret_val = true
		}
	default:
		//fmt.Println("WafUpdateRuleFlags: Invalid parameters: ", flagName, flagValue)
	}
	if ret_val == false {
		fmt.Println("WafUpdateRuleFlags: Invalid parameters : ", flagName, " or value: ", flagValue)
	}
	return ret_val
}

//MJ Changes ]
