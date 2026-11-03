import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { SeverityBadge, ConfidenceBadge, StatusBadge, KpiTile } from '../src/components/ui/primitives';
import { RiskGauge } from '../src/components/charts';

describe('SOC UI Primitives & Design Tokens', () => {
  it('renders severity badge with correct label and tone styles', () => {
    const html = renderToStaticMarkup(<SeverityBadge severity="CRITICAL" />);
    expect(html).toContain('CRITICAL');
    expect(html).toContain('border-rose-500');
  });

  it('renders confidence badge with mapped confidence tiers', () => {
    const htmlHigh = renderToStaticMarkup(<ConfidenceBadge confidence="HIGH" />);
    expect(htmlHigh).toContain('High confidence');

    const htmlLow = renderToStaticMarkup(<ConfidenceBadge confidence="LOW" />);
    expect(htmlLow).toContain('Low confidence');
  });

  it('renders status badge with appropriate semantic tone', () => {
    const htmlVerified = renderToStaticMarkup(<StatusBadge status="VERIFIED" />);
    expect(htmlVerified).toContain('Verified');
    expect(htmlVerified).toContain('border-emerald-500');

    const htmlBlocked = renderToStaticMarkup(<StatusBadge status="BLOCKED" />);
    expect(htmlBlocked).toContain('Blocked');
    expect(htmlBlocked).toContain('border-rose-500');
  });

  it('renders risk gauge svg with bounded score and calculated arc', () => {
    const html = renderToStaticMarkup(<RiskGauge score={85} band="CRITICAL" />);
    expect(html).toContain('85');
    expect(html).toContain('CRITICAL');
    expect(html).toContain('<svg');
  });

  it('renders KpiTile with formatted numeric value and hint', () => {
    const html = renderToStaticMarkup(
      <KpiTile label="Active Scans" value="12" hint="+2 from last hour" tone="info" />
    );
    expect(html).toContain('Active Scans');
    expect(html).toContain('12');
    expect(html).toContain('+2 from last hour');
  });
});
