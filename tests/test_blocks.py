"""The block contract mirror. If these break, so does every chat surface."""

from __future__ import annotations

import pytest

from lory_code_security.domain.blocks import (
    BLOCK_TYPES,
    Block,
    has_code_fence,
    has_em_dash,
    parse_blocks,
    strip_code_fences,
    validate_block,
    validate_reply,
)


def test_parses_the_enclosing_object():
    blocks = parse_blocks({"blocks": [{"type": "text", "content": "hi"}]})
    assert [b.type for b in blocks] == ["text"]
    assert blocks[0].get("content") == "hi"


def test_parses_a_bare_list():
    assert len(parse_blocks([{"type": "text", "content": "a"}, {"type": "cta"}])) == 2


def test_parses_a_json_string():
    blocks = parse_blocks('{"blocks": [{"type": "text", "content": "x"}]}')
    assert blocks[0].get("content") == "x"


def test_parses_a_fenced_json_string():
    """The skill file bans fences; the renderer still has to cope with one."""
    raw = '```json\n{"blocks": [{"type": "text", "content": "x"}]}\n```'
    assert parse_blocks(raw)[0].get("content") == "x"


def test_unparseable_text_becomes_a_text_block():
    blocks = parse_blocks("just prose, no JSON at all")
    assert blocks[0].type == "text"
    assert "just prose" in blocks[0].get("content")


def test_entry_without_a_type_defaults_to_text():
    assert parse_blocks([{"content": "orphan"}])[0].type == "text"


def test_non_object_entries_are_dropped():
    assert len(parse_blocks(["nope", 7, {"type": "text", "content": "ok"}])) == 1


@pytest.mark.parametrize("block_type", BLOCK_TYPES)
def test_every_declared_type_has_a_spec(block_type):
    problems = validate_block(Block(block_type, {}))
    assert "unknown block type" not in " ".join(problems)


def test_missing_required_key_is_reported():
    assert any("content" in p for p in validate_block(Block("text", {})))


def test_unexpected_key_is_reported():
    problems = validate_block(Block("text", {"content": "x", "colour": "red"}))
    assert any("colour" in p for p in problems)


def test_table_row_arity_is_checked():
    block = Block("table", {"headers": ["a", "b"], "rows": [["1"]]})
    assert any("row 0" in p for p in validate_block(block))


def test_chart_label_and_data_arity_is_checked():
    block = Block("chart", {"chart_type": "bar", "labels": ["a", "b"], "data": [1]})
    assert any("2 labels but 1 data" in p for p in validate_block(block))


def test_chart_type_must_be_supported():
    block = Block("chart", {"chart_type": "sankey", "labels": ["a"], "data": [1]})
    assert any("sankey" in p for p in validate_block(block))


def test_more_than_one_cta_violates_the_contract():
    blocks = [Block("cta", {"label": "a", "url": "/a"}), Block("cta", {"label": "b", "url": "/b"})]
    assert any("cta blocks" in p for p in validate_reply(blocks, []))


def test_cta_must_be_last():
    blocks = [Block("cta", {"label": "a", "url": "/a"}), Block("text", {"content": "after"})]
    assert any("must be last" in p for p in validate_reply(blocks, []))


def test_suggestion_count_bounds():
    blocks = [Block("text", {"content": "x"})]
    assert any("2 to 4" in p for p in validate_reply(blocks, ["only one"]))
    assert not validate_reply(blocks, ["one", "two"])


def test_suggestion_length_bound():
    blocks = [Block("text", {"content": "x"})]
    long = "x" * 40
    assert any("over 35 chars" in p for p in validate_reply(blocks, ["ok", long]))


def test_fence_and_dash_detection():
    assert has_code_fence("```json\n{}\n```")
    assert not has_code_fence('{"blocks": []}')
    assert has_em_dash("this — that")
    assert has_em_dash("range 1–2")
    assert not has_em_dash("this - that")


def test_strip_code_fences_is_idempotent_on_clean_json():
    assert strip_code_fences('{"a": 1}') == '{"a": 1}'


def test_text_content_walks_nested_structures():
    block = Block("report", {"title": "T", "sections": [{"heading": "H", "content": "C"}]})
    text = block.text_content()
    assert "T" in text and "H" in text and "C" in text


def test_transactional_blocks_are_flagged():
    assert Block("invoice", {}).is_transactional
    assert Block("handoff", {}).is_transactional
    assert not Block("text", {}).is_transactional
