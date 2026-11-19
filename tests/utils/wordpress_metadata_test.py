"""Release parsing and readme identity contracts shared by WordPress checks."""

from __future__ import annotations

import pytest

from agent.utils import wordpress_metadata


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", (1, 0, 0, 0)),
        ("1.3", (1, 3, 0, 0)),
        ("4.5.5.1", (4, 5, 5, 1)),
        ("0.9", (0, 9, 0, 0)),
        ("3.0.4.0", (3, 0, 4, 0)),
    ],
)
def testParseRelease_whenCanonical_normalizesWithoutTruncation(
    value: str, expected: tuple[int, ...]
) -> None:
    assert wordpress_metadata.parse_release(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        1,
        True,
        "",
        "1.2.3.4.5",
        "1.02",
        "1.2beta",
        "1.2+patched",
        " 1.2",
        "1.2 ",
        "10000",
        "١.٢",
    ],
)
def testParseRelease_whenAmbiguous_returnsNone(value: object) -> None:
    assert wordpress_metadata.parse_release(value) is None


@pytest.mark.parametrize("header", ["Version: 3.0.4\n", "Version: 3.0.4.0\n", ""])
def testParseReadme_whenConsistentExplicitVersion_keepsStableTag(header: str) -> None:
    body = f"=== Canto ===\nStable tag: 3.0.4\n{header}== Description ==\n<a href='https://example.com'>documentation</a>\n".encode()
    assert wordpress_metadata.parse_readme(body, ("Canto",)) == "3.0.4"


def testParseReadme_whenNonUtf8_returnsNone() -> None:
    assert (
        wordpress_metadata.parse_readme(
            b"=== Canto ===\nStable tag: 3.0.4\n\xff", ("Canto",)
        )
        is None
    )


def testParseReadme_whenHeadingHasVendorWhitespace_acceptsExactName() -> None:
    body = b"=== Canto  ===\nStable tag: 3.0.4\n"
    assert wordpress_metadata.parse_readme(body, ("Canto",)) == "3.0.4"


def testParseReadme_whenChangelogMentionsHtmlTitle_keepsDocumentMetadata() -> None:
    body = (
        b"=== Canto ===\nStable tag: 3.0.4\n== Changelog ==\nFix the `<title>` tag.\n"
    )
    assert wordpress_metadata.parse_readme(body, ("Canto",)) == "3.0.4"


def testParseReadme_whenTagAppearsOnlyAfterSubsection_returnsNone() -> None:
    body = b"=== Canto ===\n= 3.0.4 =\nStable tag: 3.0.4\n"
    assert wordpress_metadata.parse_readme(body, ("Canto",)) is None


@pytest.mark.parametrize(
    "heading,expected",
    [("==== KEY FEATURES ====", "1.5.6.3"), ("=== Other plugin ===", None)],
)
def testParseReadme_whenLaterHeading_distinguishesSectionsFromPluginHeaders(
    heading: str, expected: str | None
) -> None:
    body = f"=== LA-Studio Element Kit for Elementor ===\nStable tag: 1.5.6.3\n== Description ==\n{heading}\n".encode()
    assert (
        wordpress_metadata.parse_readme(body, ("LA-Studio Element Kit for Elementor",))
        == expected
    )
