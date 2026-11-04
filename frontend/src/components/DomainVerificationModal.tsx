import React, { useState } from 'react';
import {
  ShieldCheck,
  Globe,
  Copy,
  Check,
  AlertTriangle,
  FileCode,
  Radio,
  X,
  ExternalLink,
  RefreshCw,
  Lock,
} from 'lucide-react';
import type { WebsiteAsset } from '@veltrix/shared';
import { verifyDomain } from '../lib/api/endpoints';
import { Button, Badge } from './ui/primitives';

export interface DomainVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
  site: WebsiteAsset;
  onSuccess?: () => void;
}

export function DomainVerificationModal({
  isOpen,
  onClose,
  site,
  onSuccess,
}: DomainVerificationModalProps) {
  const [selectedMethod, setSelectedMethod] = useState<'DNS_TXT' | 'HTTP_CHALLENGE' | 'META_TAG'>('DNS_TXT');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const dnsTxtRecordValue = site.dnsTxtRecord || `veltrix-domain-verification=${site.verificationToken || 'token'}`;
  const dnsTxtHost = `_veltrix-challenge.${site.primaryDomain}`;
  const httpPath = site.httpChallenge?.path || '/.well-known/veltrix-challenge.txt';
  const httpExpectedBody = site.httpChallenge?.expectedBody || site.verificationToken || 'token';
  const metaTagContent = site.metaTag || `<meta name="veltrix-domain-verification" content="${site.verificationToken || 'token'}">`;

  const handleVerify = async () => {
    try {
      setIsSubmitting(true);
      setErrorMessage(null);
      setSuccessMessage(null);

      const res = await verifyDomain(site.siteId, selectedMethod);
      if (res.verified) {
        setSuccessMessage(res.message || 'Domain ownership verified successfully! Active scanning is now authorized.');
        if (onSuccess) {
          setTimeout(() => {
            onSuccess();
            onClose();
          }, 1500);
        }
      } else {
        setErrorMessage(res.message || 'Verification could not confirm domain ownership.');
      }
    } catch (err: unknown) {
      setErrorMessage((err as Error)?.message || 'Failed to complete verification request.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="w-full max-w-2xl rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-500/10 text-cyan-400">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                Verify Domain Ownership
                <Badge tone="cyan">{site.primaryDomain}</Badge>
              </h2>
              <p className="text-xs text-slate-400">
                Prove domain administrative ownership to unlock automated crawling and active security probes.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Scan Block Notice */}
          <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 text-amber-300 text-xs">
            <Lock className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
            <div>
              <span className="font-semibold text-amber-200">Security Gate Active:</span> In compliance with ethical penetration testing standards, VELTRIX restricts non-destructive active probes until domain ownership is validated.
            </div>
          </div>

          {/* Method Tabs */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              Choose Verification Method
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setSelectedMethod('DNS_TXT')}
                className={`flex flex-col items-center justify-center p-3 rounded-xl border text-xs font-semibold transition-all ${
                  selectedMethod === 'DNS_TXT'
                    ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300 shadow-sm shadow-cyan-500/20'
                    : 'border-slate-800 bg-slate-950/40 text-slate-400 hover:border-slate-700'
                }`}
              >
                <Radio className="h-4 w-4 mb-1.5" />
                DNS TXT Record
                <span className="text-[10px] text-slate-400 mt-0.5">(Recommended)</span>
              </button>

              <button
                type="button"
                onClick={() => setSelectedMethod('HTTP_CHALLENGE')}
                className={`flex flex-col items-center justify-center p-3 rounded-xl border text-xs font-semibold transition-all ${
                  selectedMethod === 'HTTP_CHALLENGE'
                    ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300 shadow-sm shadow-cyan-500/20'
                    : 'border-slate-800 bg-slate-950/40 text-slate-400 hover:border-slate-700'
                }`}
              >
                <Globe className="h-4 w-4 mb-1.5" />
                HTTP Challenge
                <span className="text-[10px] text-slate-400 mt-0.5">File Upload</span>
              </button>

              <button
                type="button"
                onClick={() => setSelectedMethod('META_TAG')}
                className={`flex flex-col items-center justify-center p-3 rounded-xl border text-xs font-semibold transition-all ${
                  selectedMethod === 'META_TAG'
                    ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300 shadow-sm shadow-cyan-500/20'
                    : 'border-slate-800 bg-slate-950/40 text-slate-400 hover:border-slate-700'
                }`}
              >
                <FileCode className="h-4 w-4 mb-1.5" />
                HTML Meta Tag
                <span className="text-[10px] text-slate-400 mt-0.5">Homepage &lt;head&gt;</span>
              </button>
            </div>
          </div>

          {/* Instructions Content */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
            {selectedMethod === 'DNS_TXT' && (
              <>
                <p className="text-xs text-slate-300">
                  Add the following <code className="text-cyan-400 font-mono">TXT</code> record to your DNS provider (Cloudflare, Route53, GoDaddy, etc.):
                </p>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Host / Name</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-white">
                    <span className="truncate">{dnsTxtHost}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(dnsTxtHost, 'host')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Host"
                    >
                      {copiedKey === 'host' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">TXT Record Value</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-cyan-300">
                    <span className="truncate">{dnsTxtRecordValue}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(dnsTxtRecordValue, 'txtval')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Value"
                    >
                      {copiedKey === 'txtval' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>
              </>
            )}

            {selectedMethod === 'HTTP_CHALLENGE' && (
              <>
                <p className="text-xs text-slate-300">
                  Upload a plain text file accessible via public HTTP(S) at:
                </p>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">File Path URL</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-white">
                    <span className="truncate">{`https://${site.primaryDomain}${httpPath}`}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(`https://${site.primaryDomain}${httpPath}`, 'httppath')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Path"
                    >
                      {copiedKey === 'httppath' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Expected File Body</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-cyan-300">
                    <span className="truncate">{httpExpectedBody}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(httpExpectedBody, 'httpbody')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Body"
                    >
                      {copiedKey === 'httpbody' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>
              </>
            )}

            {selectedMethod === 'META_TAG' && (
              <>
                <p className="text-xs text-slate-300">
                  Add the following meta tag inside the <code className="text-cyan-400 font-mono">&lt;head&gt;</code> element of your homepage (<code className="text-slate-400 font-mono">/</code>):
                </p>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">HTML Tag</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-cyan-300">
                    <span className="truncate">{metaTagContent}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(metaTagContent, 'metatag')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Tag"
                    >
                      {copiedKey === 'metatag' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Feedback messages */}
          {errorMessage && (
            <div className="flex items-start gap-2.5 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-300">
              <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="flex items-start gap-2.5 rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-300">
              <Check className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
              <span>{successMessage}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-800 bg-slate-950/40 px-6 py-4">
          <Button variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={handleVerify}
            disabled={isSubmitting}
            icon={RefreshCw}
          >
            {isSubmitting ? 'Verifying...' : 'Verify Ownership Now'}
          </Button>
        </div>
      </div>
    </div>
  );
}
