"""Offline conversion: backend resolution, status classification, and framing."""

from __future__ import annotations

from typing import Any

import pytest
from tests.conftest import SAMPLE_RULE_TEXT, make_rule

from sigma_detection_engineering_lab.config import (
    BackendConfig,
    ConversionConfig,
    LabConfig,
    load_conversion_config,
)
from sigma_detection_engineering_lab.constants import CONVERSION_DEMONSTRATION_BANNER
from sigma_detection_engineering_lab.conversion import (
    UNSUPPORTED_MARKERS,
    BackendHandle,
    ConversionSet,
    convert_catalog,
    convert_rule,
    load_backend,
    load_backends,
    render_query_block,
)
from sigma_detection_engineering_lab.models import ConversionResult, ConversionStatus
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog


def backend_settings(**overrides: Any) -> BackendConfig:
    values: dict[str, Any] = {
        "key": "splunk",
        "enabled": True,
        "package": "pysigma-backend-splunk",
        "version": "1.1.0",
        "backend_class": "sigma.backends.splunk.SplunkBackend",
        "dialect": "SPL",
        "demonstration_banner": "DEMONSTRATION ONLY",
    }
    values.update(overrides)
    return BackendConfig(**values)


class StubBackend:
    """A backend stand-in, so classification is tested without pySigma installed."""

    def __init__(self, behaviour: Any = "index=main Image=*") -> None:
        self.behaviour = behaviour

    def convert(self, collection: Any) -> Any:
        if isinstance(self.behaviour, Exception):
            raise self.behaviour
        return self.behaviour


def stub_handle(behaviour: Any = "index=main Image=*", **overrides: Any) -> BackendHandle:
    return BackendHandle(
        key="splunk",
        settings=backend_settings(**overrides),
        backend=StubBackend(behaviour),
        available=True,
    )


def convertible_rule(**overrides: Any) -> Any:
    return make_rule(raw_text=SAMPLE_RULE_TEXT, **overrides)


def pysigma_installed() -> bool:
    try:
        import sigma.collection  # noqa: F401
    except ImportError:
        return False
    return True


needs_pysigma = pytest.mark.skipif(not pysigma_installed(), reason="pySigma is not installed")


class TestBackendResolution:
    def test_a_disabled_backend_is_unavailable(self) -> None:
        handle = load_backend(backend_settings(enabled=False))
        assert handle.available is False

    def test_a_disabled_backend_explains_itself(self) -> None:
        handle = load_backend(backend_settings(enabled=False))
        assert "disabled" in handle.error

    def test_an_absent_package_is_unavailable(self) -> None:
        handle = load_backend(
            backend_settings(backend_class="sigma.backends.nonexistent.NopeBackend")
        )
        assert handle.available is False

    def test_an_absent_package_names_the_pinned_version(self) -> None:
        handle = load_backend(
            backend_settings(backend_class="sigma.backends.nonexistent.NopeBackend")
        )
        assert "1.1.0" in handle.error

    def test_a_missing_class_is_unavailable(self) -> None:
        handle = load_backend(backend_settings(backend_class="json.NotAClass"))
        assert handle.available is False

    def test_a_backend_that_cannot_be_instantiated_is_unavailable(self) -> None:
        handle = load_backend(backend_settings(backend_class="json.JSONDecodeError"))
        assert handle.available is False

    def test_resolution_never_raises(self) -> None:
        assert load_backend(backend_settings(backend_class="a.b.C")).available is False

    def test_the_handle_keeps_its_key(self) -> None:
        assert load_backend(backend_settings(key="elastic", enabled=False)).key == "elastic"

    def test_the_handle_serialises(self) -> None:
        payload = load_backend(backend_settings(enabled=False)).to_dict()
        assert set(payload) == {
            "key",
            "available",
            "error",
            "package",
            "version",
            "dialect",
            "backend_class",
        }

    def test_every_configured_backend_is_resolved(self) -> None:
        settings = ConversionConfig(
            backends=(backend_settings(key="a", enabled=False), backend_settings(key="b"))
        )
        assert len(load_backends(settings)) == 2

    def test_an_empty_configuration_resolves_nothing(self) -> None:
        assert load_backends(ConversionConfig()) == ()


class TestBackendConfigHelpers:
    def test_the_module_path_is_derived(self) -> None:
        assert backend_settings().module_path == "sigma.backends.splunk"

    def test_the_class_name_is_derived(self) -> None:
        assert backend_settings().class_name == "SplunkBackend"

    def test_enabled_backends_are_filtered(self) -> None:
        settings = ConversionConfig(
            backends=(backend_settings(key="a"), backend_settings(key="b", enabled=False))
        )
        assert [backend.key for backend in settings.enabled_backends()] == ["a"]

    def test_a_backend_can_be_fetched_by_key(self) -> None:
        settings = ConversionConfig(backends=(backend_settings(key="a"),))
        assert settings.get("a") is not None

    def test_an_unknown_key_returns_none(self) -> None:
        assert ConversionConfig().get("nope") is None

    def test_the_configuration_serialises(self) -> None:
        payload = ConversionConfig(backends=(backend_settings(),)).to_dict()
        assert payload["backends"][0]["key"] == "splunk"

    def test_correlation_is_unsupported_by_default(self) -> None:
        assert ConversionConfig().correlation_supported is False


class TestStatusClassification:
    def test_an_unavailable_backend_is_reported_as_such(self) -> None:
        handle = BackendHandle(key="splunk", settings=backend_settings(), available=False)
        result = convert_rule(convertible_rule(), handle)
        assert result.status is ConversionStatus.BACKEND_UNAVAILABLE

    def test_an_unavailable_backend_is_never_a_success(self) -> None:
        handle = BackendHandle(key="splunk", settings=backend_settings(), available=False)
        assert convert_rule(convertible_rule(), handle).status is not ConversionStatus.CONVERTED

    def test_a_rule_without_source_text_is_an_error(self) -> None:
        result = convert_rule(make_rule(raw_text=""), stub_handle())
        assert result.status is ConversionStatus.ERROR

    def test_the_missing_source_is_explained(self) -> None:
        result = convert_rule(make_rule(raw_text=""), stub_handle())
        assert "source text is unavailable" in result.message

    @needs_pysigma
    def test_a_successful_conversion_produces_queries(self) -> None:
        result = convert_rule(convertible_rule(), stub_handle())
        assert result.status is ConversionStatus.CONVERTED
        assert result.queries == ("index=main Image=*",)

    @needs_pysigma
    def test_an_empty_query_is_unsupported(self) -> None:
        result = convert_rule(convertible_rule(), stub_handle(behaviour=[]))
        assert result.status is ConversionStatus.UNSUPPORTED

    @needs_pysigma
    def test_a_blank_query_string_is_unsupported(self) -> None:
        result = convert_rule(convertible_rule(), stub_handle(behaviour="   "))
        assert result.status is ConversionStatus.UNSUPPORTED

    @needs_pysigma
    def test_a_refusal_is_classified_as_unsupported(self) -> None:
        handle = stub_handle(behaviour=ValueError("this construct is not supported"))
        assert convert_rule(convertible_rule(), handle).status is ConversionStatus.UNSUPPORTED

    @needs_pysigma
    def test_an_unexpected_failure_is_classified_as_an_error(self) -> None:
        handle = stub_handle(behaviour=RuntimeError("segmentation of the widget"))
        assert convert_rule(convertible_rule(), handle).status is ConversionStatus.ERROR

    @needs_pysigma
    def test_a_correlation_refusal_is_explained(self) -> None:
        rule = convertible_rule(is_correlation=True, correlation={"type": "event_count"})
        handle = stub_handle(behaviour=RuntimeError("boom"))
        result = convert_rule(rule, handle)
        assert result.status is ConversionStatus.UNSUPPORTED
        assert "correlation conversion is not supported" in result.message

    @needs_pysigma
    def test_correlation_support_can_be_declared(self) -> None:
        rule = convertible_rule(is_correlation=True, correlation={"type": "event_count"})
        handle = stub_handle(behaviour=RuntimeError("boom"))
        result = convert_rule(rule, handle, correlation_supported=True)
        assert result.status is ConversionStatus.ERROR

    @needs_pysigma
    def test_unparseable_rule_text_is_an_error(self) -> None:
        result = convert_rule(make_rule(raw_text="::: not yaml :::"), stub_handle())
        assert result.status is ConversionStatus.ERROR

    @needs_pysigma
    def test_nested_query_lists_are_flattened(self) -> None:
        handle = stub_handle(behaviour=[["a"], ["b", "c"]])
        assert convert_rule(convertible_rule(), handle).queries == ("a", "b", "c")

    @needs_pysigma
    def test_a_non_string_query_is_stringified(self) -> None:
        assert convert_rule(convertible_rule(), stub_handle(behaviour=42)).queries == ("42",)

    @needs_pysigma
    def test_a_none_result_is_unsupported(self) -> None:
        assert (
            convert_rule(convertible_rule(), stub_handle(behaviour=None)).status
            is ConversionStatus.UNSUPPORTED
        )

    @pytest.mark.parametrize("marker", UNSUPPORTED_MARKERS)
    def test_every_refusal_marker_is_recognised(self, marker: str) -> None:
        from sigma_detection_engineering_lab.conversion import _looks_unsupported

        assert _looks_unsupported(f"Backend error: {marker.upper()} here") is True

    def test_an_unrelated_message_is_not_a_refusal(self) -> None:
        from sigma_detection_engineering_lab.conversion import _looks_unsupported

        assert _looks_unsupported("connection reset") is False


class TestResultFraming:
    def test_every_result_carries_a_banner(self) -> None:
        handle = BackendHandle(key="splunk", settings=backend_settings(), available=False)
        assert convert_rule(convertible_rule(), handle).banner

    def test_the_configured_banner_wins(self) -> None:
        settings = backend_settings(demonstration_banner="CUSTOM BANNER", enabled=False)
        handle = BackendHandle(key="splunk", settings=settings, available=False)
        assert convert_rule(convertible_rule(), handle).banner == "CUSTOM BANNER"

    def test_the_default_banner_is_used_when_none_is_configured(self) -> None:
        settings = backend_settings(demonstration_banner="", enabled=False)
        handle = BackendHandle(key="splunk", settings=settings, available=False)
        assert convert_rule(convertible_rule(), handle).banner == CONVERSION_DEMONSTRATION_BANNER

    def test_the_backend_version_is_recorded(self) -> None:
        handle = BackendHandle(key="splunk", settings=backend_settings(), available=False)
        assert convert_rule(convertible_rule(), handle).backend_version == "1.1.0"

    def test_the_dialect_is_recorded(self) -> None:
        handle = BackendHandle(key="splunk", settings=backend_settings(), available=False)
        assert convert_rule(convertible_rule(), handle).dialect == "SPL"

    def test_the_catalog_id_is_recorded(self) -> None:
        handle = BackendHandle(key="splunk", settings=backend_settings(), available=False)
        rule = convertible_rule(catalog_id="SDEL-WIN-042")
        assert convert_rule(rule, handle).catalog_id == "SDEL-WIN-042"


class TestConversionSet:
    def make_set(self, *results: ConversionResult) -> ConversionSet:
        return ConversionSet(results=tuple(results), handles=(stub_handle(),))

    def result(self, **overrides: Any) -> ConversionResult:
        values: dict[str, Any] = {
            "catalog_id": "A",
            "backend": "splunk",
            "status": ConversionStatus.CONVERTED,
            "queries": ("q",),
        }
        values.update(overrides)
        return ConversionResult(**values)

    def test_results_can_be_filtered_by_rule(self) -> None:
        conversions = self.make_set(self.result(), self.result(catalog_id="B"))
        assert len(conversions.for_rule("A")) == 1

    def test_results_can_be_filtered_by_backend(self) -> None:
        conversions = self.make_set(self.result(), self.result(backend="elastic"))
        assert len(conversions.for_backend("elastic")) == 1

    def test_counts_cover_every_status(self) -> None:
        assert set(ConversionSet().counts()) == {str(status) for status in ConversionStatus}

    def test_counts_are_accurate(self) -> None:
        conversions = self.make_set(self.result(), self.result(status=ConversionStatus.UNSUPPORTED))
        assert conversions.counts()["converted"] == 1
        assert conversions.counts()["unsupported"] == 1

    def test_availability_is_reported(self) -> None:
        assert self.make_set().any_backend_available is True

    def test_no_handles_means_nothing_is_available(self) -> None:
        assert ConversionSet().any_backend_available is False

    def test_the_document_denies_production_readiness(self) -> None:
        assert ConversionSet().to_dict()["production_ready"] is False

    def test_the_document_carries_a_disclaimer(self) -> None:
        assert ConversionSet().to_dict()["disclaimer"]

    def test_the_document_carries_the_banner(self) -> None:
        assert ConversionSet().to_dict()["banner"] == CONVERSION_DEMONSTRATION_BANNER

    def test_the_document_states_correlation_support(self) -> None:
        assert ConversionSet().to_dict()["correlation_conversion_supported"] is False

    def test_the_document_lists_backends(self) -> None:
        assert len(self.make_set().to_dict()["backends"]) == 1

    def test_the_document_lists_results(self) -> None:
        assert len(self.make_set(self.result()).to_dict()["results"]) == 1


class TestConvertCatalog:
    def test_every_rule_is_attempted(self, tiny_config: LabConfig) -> None:
        settings = ConversionConfig(backends=(backend_settings(),))
        catalog = RuleCatalog([make_rule("a", rule_id="a"), make_rule("b", rule_id="b")])
        conversions = convert_catalog(catalog, config=tiny_config, conversion_config=settings)
        assert {result.catalog_id for result in conversions.results} == {"a", "b"}

    def test_the_only_filter_narrows_the_run(self, tiny_config: LabConfig) -> None:
        settings = ConversionConfig(backends=(backend_settings(),))
        catalog = RuleCatalog([make_rule("a", rule_id="a"), make_rule("b", rule_id="b")])
        conversions = convert_catalog(
            catalog, config=tiny_config, conversion_config=settings, only=["a"]
        )
        assert {result.catalog_id for result in conversions.results} == {"a"}

    def test_the_backend_filter_narrows_the_run(self, tiny_config: LabConfig) -> None:
        settings = ConversionConfig(backends=(backend_settings(key="a"), backend_settings(key="b")))
        conversions = convert_catalog(
            RuleCatalog([make_rule()]),
            config=tiny_config,
            conversion_config=settings,
            backend_keys=["a"],
        )
        assert {result.backend for result in conversions.results} == {"a"}

    def test_no_backends_means_no_results(self, tiny_config: LabConfig) -> None:
        conversions = convert_catalog(
            RuleCatalog([make_rule()]), config=tiny_config, conversion_config=ConversionConfig()
        )
        assert conversions.results == ()

    def test_an_empty_catalog_produces_no_results(self, tiny_config: LabConfig) -> None:
        settings = ConversionConfig(backends=(backend_settings(),))
        conversions = convert_catalog(
            RuleCatalog([]), config=tiny_config, conversion_config=settings
        )
        assert conversions.results == ()

    def test_the_set_is_timestamped(self, tiny_config: LabConfig) -> None:
        conversions = convert_catalog(
            RuleCatalog([]), config=tiny_config, conversion_config=ConversionConfig()
        )
        assert conversions.generated_at.endswith("Z")

    def test_a_missing_backend_config_yields_an_empty_configuration(
        self, tiny_config: LabConfig
    ) -> None:
        assert load_conversion_config(tiny_config).backends == ()


class TestQueryRendering:
    def result(self, **overrides: Any) -> ConversionResult:
        values: dict[str, Any] = {
            "catalog_id": "SDEL-WIN-001",
            "backend": "splunk",
            "status": ConversionStatus.CONVERTED,
            "queries": ("index=main Image=*",),
            "banner": "DEMONSTRATION ONLY",
            "dialect": "SPL",
        }
        values.update(overrides)
        return ConversionResult(**values)

    def test_the_banner_is_the_first_line(self) -> None:
        assert render_query_block(self.result()).splitlines()[0] == "# DEMONSTRATION ONLY"

    def test_the_rule_is_named(self) -> None:
        assert "# rule: SDEL-WIN-001" in render_query_block(self.result())

    def test_the_backend_and_dialect_are_named(self) -> None:
        assert "# backend: splunk (SPL)" in render_query_block(self.result())

    def test_an_unknown_dialect_is_labelled(self) -> None:
        assert "unknown dialect" in render_query_block(self.result(dialect=None))

    def test_the_status_is_stated(self) -> None:
        assert "# status: converted" in render_query_block(self.result())

    def test_production_readiness_is_denied(self) -> None:
        assert "# production_ready: false" in render_query_block(self.result())

    def test_the_query_text_is_included(self) -> None:
        assert "index=main Image=*" in render_query_block(self.result())

    def test_a_note_is_rendered_when_present(self) -> None:
        assert "# note: careful" in render_query_block(self.result(message="careful"))

    def test_an_absent_query_is_stated_explicitly(self) -> None:
        rendered = render_query_block(self.result(queries=(), status=ConversionStatus.UNSUPPORTED))
        assert "# (no query produced)" in rendered

    def test_every_line_of_metadata_is_commented(self) -> None:
        lines = render_query_block(self.result(queries=())).splitlines()
        assert all(line.startswith("#") for line in lines)


class TestRealConversion:
    def test_the_real_backend_config_loads(self, real_config: LabConfig) -> None:
        assert load_conversion_config(real_config).backends

    def test_every_real_backend_declares_a_pinned_version(self, real_config: LabConfig) -> None:
        settings = load_conversion_config(real_config)
        assert all(backend.version for backend in settings.backends)

    def test_every_real_backend_declares_a_banner(self, real_config: LabConfig) -> None:
        settings = load_conversion_config(real_config)
        assert all(backend.demonstration_banner for backend in settings.backends)

    def test_correlation_conversion_is_not_claimed(self, real_config: LabConfig) -> None:
        assert load_conversion_config(real_config).correlation_supported is False

    def test_a_real_run_classifies_every_rule(
        self, real_config: LabConfig, real_catalog: RuleCatalog
    ) -> None:
        conversions = convert_catalog(real_catalog, config=real_config, only=["SDEL-WIN-001"])
        assert all(result.status in set(ConversionStatus) for result in conversions.results)

    def test_a_real_run_never_claims_production_readiness(
        self, real_config: LabConfig, real_catalog: RuleCatalog
    ) -> None:
        conversions = convert_catalog(real_catalog, config=real_config, only=["SDEL-WIN-001"])
        assert conversions.to_dict()["production_ready"] is False
