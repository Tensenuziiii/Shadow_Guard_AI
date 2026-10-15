import pytest

from app.security.registry import effective_trust_zone


@pytest.mark.parametrize(
    ('configured_zone', 'classification', 'expected'),
    [
        ('HIGH', 'LOW_TRUST', 'HIGH'),
        ('MEDIUM', 'LOW_TRUST', 'MEDIUM'),
        ('LOW', 'HIGH_TRUST', 'HIGH'),
        ('HIGH', 'HIGH_TRUST', 'HIGH'),
    ],
)
def test_effective_trust_zone_uses_the_higher_configured_or_calculated_zone(
    configured_zone, classification, expected
):
    assert effective_trust_zone(configured_zone, classification) == expected


def test_effective_trust_zone_rejects_unknown_configuration():
    with pytest.raises(ValueError, match='Unsupported configured trust zone'):
        effective_trust_zone('UNKNOWN', 'LOW_TRUST')


def test_effective_trust_zone_rejects_unknown_classification():
    with pytest.raises(ValueError, match='Unsupported trust classification'):
        effective_trust_zone('LOW', 'UNKNOWN')
