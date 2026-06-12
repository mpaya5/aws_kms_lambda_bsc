import pytest

from signing_core import (
    BSC_CHAIN_IDS,
    SECP256_K1_N,
    compute_eip155_v,
    get_tx_params,
    normalize_signature_s,
    resolve_chain_id,
)


class TestNormalizeSignatureS:
    def test_low_s_unchanged(self):
        assert normalize_signature_s(12345) == 12345

    def test_high_s_is_flipped_per_eip2(self):
        high_s = SECP256_K1_N - 100
        assert normalize_signature_s(high_s) == 100


class TestComputeEip155V:
    def test_bsc_mainnet_recovery_27(self):
        assert compute_eip155_v(27, 56) == 147

    def test_bsc_testnet_recovery_28(self):
        assert compute_eip155_v(28, 97) == 230


class TestResolveChainId:
    def test_explicit_chain_id_overrides_network(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", "97")
        monkeypatch.setenv("ETH_NETWORK", "bsc")
        assert resolve_chain_id() == 97

    def test_bsc_mainnet_alias(self, monkeypatch):
        monkeypatch.delenv("CHAIN_ID", raising=False)
        assert resolve_chain_id("bsc-mainnet") == BSC_CHAIN_IDS["bsc"]

    def test_chapel_testnet_alias(self, monkeypatch):
        monkeypatch.delenv("CHAIN_ID", raising=False)
        assert resolve_chain_id("chapel") == 97

    def test_unknown_network_raises(self, monkeypatch):
        monkeypatch.delenv("CHAIN_ID", raising=False)
        with pytest.raises(ValueError, match="unsupported ETH_NETWORK"):
            resolve_chain_id("ropsten")


class TestGetTxParams:
    def test_builds_legacy_tx_without_private_key(self):
        event = {
            "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            "nonce": 0,
            "gas": 21000,
            "gasPrice": 5_000_000_000,
            "data": "0x",
            "value": 0,
        }

        tx = get_tx_params(event, chain_id=56)

        assert "privateKey" not in tx
        assert tx["chainId"] == 56
        assert tx["gasPrice"] == 5_000_000_000

    def test_missing_fields_return_error(self):
        result = get_tx_params({"to": "0x0"}, chain_id=97)
        assert "error" in result
        assert "missing parameter" in result["error"]

    def test_rejects_secret_fields(self):
        event = {
            "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            "nonce": 0,
            "gas": 21000,
            "gasPrice": 5_000_000_000,
            "data": "0x",
            "privateKey": "0xdeadbeef",
        }
        result = get_tx_params(event, chain_id=97)
        assert "error" in result
        assert "secret key material" in result["error"]

