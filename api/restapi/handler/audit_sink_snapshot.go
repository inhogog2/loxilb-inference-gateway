/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handler

import (
	"context"
	"errors"
	"sort"

	"github.com/loxilb-io/loxilb/api/models"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/loxilb-io/loxilb/pkg/audit/syslog"
)

// The sinks as the configuration snapshot sees them. A sink is captured as
// what an operator configured: the receiver, the paths of the certificate
// material and, for a secondary sink, its selection. Applying one goes
// through the same checks as the request that configures it, so a sink a
// request would refuse is refused here too, and it continues from the place
// and the export sequence this node keeps under its name.

func auditSinkConfigOf(name string, cfg syslog.Config, filter audit.SinkFilter) cmn.AuditSinkConfig {
	out := cmn.AuditSinkConfig{
		Name:             name,
		Address:          cfg.Address,
		CABundlePath:     cfg.CABundlePath,
		ServerName:       cfg.ServerName,
		ClientCertPath:   cfg.ClientCertPath,
		ClientKeyPath:    cfg.ClientKeyPath,
		MaxFrameBytes:    cfg.MaxFrameBytes,
		Facility:         cfg.Facility,
		EnterpriseNumber: cfg.EnterpriseNumber,
	}
	if len(filter.Streams) > 0 || len(filter.Services) > 0 || filter.Outcome != "" || filter.DataSample > 1 {
		f := &cmn.AuditSinkFilter{
			Services:   append([]string(nil), filter.Services...),
			Outcome:    filter.Outcome,
			DataSample: filter.DataSample,
		}
		for _, s := range filter.Streams {
			f.Streams = append(f.Streams, string(s))
		}
		out.Filter = f
	}
	return out
}

// AuditSinkExport returns every configured sink, the compliance sink first
// and the secondary ones by name.
func AuditSinkExport() []cmn.AuditSinkConfig {
	auditSink.mu.Lock()
	defer auditSink.mu.Unlock()
	var out []cmn.AuditSinkConfig
	if auditSink.sink != nil {
		out = append(out, auditSinkConfigOf(cmn.AuditSinkCompliance, auditSink.cfg, audit.SinkFilter{}))
	}
	names := make([]string, 0, len(auditSink.named))
	for name := range auditSink.named {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ns := auditSink.named[name]
		out = append(out, auditSinkConfigOf(name, ns.cfg, ns.filter))
	}
	return out
}

// AuditSinkApply configures the sink c names, replacing one of that name.
// A sink is not held without a trail to feed it: the error then says the
// trail is not running, which a restore at start takes as not yet.
func AuditSinkApply(c *cmn.AuditSinkConfig) error {
	if c == nil {
		return errors.New("audit sink: nil config")
	}
	ctx := context.Background()
	if c.Name == cmn.AuditSinkCompliance {
		// The compliance sink receives every record under no export
		// sequence; a document that gives it either was not captured here.
		if c.EnterpriseNumber != 0 || c.Filter != nil {
			return errors.New("audit sink compliance: refused: it takes no enterprise_number and no filter")
		}
		_, _, err := setAuditComplianceSink(ctx, &models.AuditSink{
			Enabled:        true,
			Address:        c.Address,
			CaBundlePath:   c.CABundlePath,
			ServerName:     c.ServerName,
			ClientCertPath: c.ClientCertPath,
			ClientKeyPath:  c.ClientKeyPath,
			MaxFrameBytes:  int64(c.MaxFrameBytes),
			Facility:       int64(c.Facility),
		}, true)
		if err != nil {
			return errors.New("audit sink compliance: " + err.Error())
		}
		return nil
	}
	m := &models.AuditNamedSink{
		Address:          c.Address,
		CaBundlePath:     c.CABundlePath,
		ServerName:       c.ServerName,
		ClientCertPath:   c.ClientCertPath,
		ClientKeyPath:    c.ClientKeyPath,
		MaxFrameBytes:    int64(c.MaxFrameBytes),
		Facility:         int64(c.Facility),
		EnterpriseNumber: int64(c.EnterpriseNumber),
	}
	if f := c.Filter; f != nil {
		if f.DataSample > 1<<62 {
			return errors.New("audit sink " + c.Name + ": refused: filter.data_sample out of range")
		}
		m.Filter = &models.AuditSinkFilter{
			Streams:    f.Streams,
			Services:   f.Services,
			Outcome:    f.Outcome,
			DataSample: int64(f.DataSample),
		}
	}
	if _, _, err := setAuditNamedSink(ctx, c.Name, m); err != nil {
		return errors.New("audit sink " + c.Name + ": " + err.Error())
	}
	return nil
}

// AuditSinkRemove ends the sink of that name. Its place in the trail and
// its export sequence stay on disk. A sink that is not configured is not
// an error: there is nothing left to end.
func AuditSinkRemove(name string) error {
	ctx := context.Background()
	if name == cmn.AuditSinkCompliance {
		if _, _, err := setAuditComplianceSink(ctx, &models.AuditSink{}, false); err != nil {
			return errors.New("audit sink compliance: " + err.Error())
		}
		return nil
	}
	if _, _, err := removeAuditNamedSink(ctx, name); err != nil {
		return errors.New("audit sink " + name + ": " + err.Error())
	}
	return nil
}
