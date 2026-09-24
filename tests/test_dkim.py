import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import analyze_dkim_coverage  # noqa: E402
from mailtrace.parsing.sample import SAMPLE_HEADERS_DKIM  # noqa: E402

try:  # Flask 相关测试在未安装 Flask 时跳过（解析核心仅需标准库）
    from app import create_app
except ImportError:  # pragma: no cover
    create_app = None


def dkim(h_list, extra="", d="example.com", s="sel2026"):
    """构造一条带 h= 的 DKIM-Signature，后接 extra 头部。"""
    return (
        f"DKIM-Signature: v=1; a=rsa-sha256; d={d}; s={s};\n"
        f"\th={h_list}; bh=aGFzaA==; b=c2lnbmF0dXJl\n"
        f"{extra}"
    )


class NoSignatureTests(unittest.TestCase):
    def test_no_dkim_returns_independent_none_status(self):
        result = analyze_dkim_coverage(
            "Received: by mx.example; Tue, 23 Sep 2026 02:00:00 +0000\n"
            "From: a@b.c\nSubject: hi\n"
        )
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["status_label"], "无 DKIM 签名")
        self.assertEqual(result["signature_count"], 0)
        self.assertEqual(result["anomaly_count"], 0)
        self.assertEqual(result["signatures"], [])
        self.assertIn("note", result)

    def test_dkim_after_body_ignored(self):
        raw = "Subject: hi\n\n" + dkim("From")
        result = analyze_dkim_coverage(raw)
        self.assertEqual(result["status"], "none")


class BasicCoverageTests(unittest.TestCase):
    def test_simple_signature_matches_in_order_bottom_up(self):
        raw = dkim(
            "From:To:Subject:Date",
            "Date: Tue, 23 Sep 2026 02:00:00 +0000\n"
            "From: a@b.c\nTo: c@d.e\nSubject: hello\n",
        )
        result = analyze_dkim_coverage(raw)
        self.assertEqual(result["status"], "audited")
        self.assertEqual(result["signature_count"], 1)
        self.assertEqual(result["anomaly_count"], 0)
        sig = result["signatures"][0]
        self.assertEqual(sig["position"], 1)
        self.assertEqual(sig["domain"], "example.com")
        self.assertEqual([m["name"] for m in sig["matches"]],
                         ["From", "To", "Subject", "Date"])
        self.assertTrue(all(m["matched"] for m in sig["matches"]))
        # 全部实际字段都在签名字段下方（签名之后追加的头部）
        self.assertTrue(all(m["relative"] == "below" for m in sig["matches"]))
        self.assertEqual(sig["unmatched_entries"], [])
        self.assertEqual(sig["uncovered_targets"], [])
        self.assertEqual(sig["target_uncovered_count"], 0)

    def test_positions_count_from_top_one_based(self):
        raw = dkim("From:X-Mid", "X-Mid: 1\nFrom: a@b.c\n")
        sig = analyze_dkim_coverage(raw)["signatures"][0]
        by_name = {m["name"]: m for m in sig["matches"]}
        self.assertEqual(by_name["From"]["position"], 3)
        self.assertEqual(by_name["X-Mid"]["position"], 2)

    def test_field_names_case_insensitive(self):
        raw = (
            "DKIM-Signature: d=e.com; h=from:TO; b=x\n"
            "FROM: a@b.c\nto: c@d.e\n"
        )
        sig = analyze_dkim_coverage(raw)["signatures"][0]
        self.assertTrue(all(m["matched"] for m in sig["matches"]))

    def test_folded_h_list_is_parsed(self):
        raw = (
            "DKIM-Signature: v=1; d=e.com;\n"
            "\th=From:Subject:Date;\n"
            "\tb=xx\n"
            "From: a@b.c\nSubject: s\nDate: Tue, 23 Sep 2026 02:00:00 +0000\n"
        )
        sig = analyze_dkim_coverage(raw)["signatures"][0]
        self.assertEqual(sig["h_count"], 3)
        self.assertTrue(all(m["matched"] for m in sig["matches"]))
        # 原始折行文本保留
        self.assertIn("\n", sig["raw"])


class DuplicateHeaderTests(unittest.TestCase):
    def test_duplicate_field_names_not_collapsed_as_set(self):
        # h= 中 Received 出现三次，实际也有三个；每个 h 项消费不同副本，
        # 从底部向上匹配，位置必须互不相同。
        raw = (
            "DKIM-Signature: d=e.com; h=Received:Received:Received; b=x\n"
            "Received: by hop1\n"
            "Received: by hop2\n"
            "Received: by hop3\n"
        )
        sig = analyze_dkim_coverage(raw)["signatures"][0]
        positions = [m["position"] for m in sig["matches"]]
        self.assertEqual(positions, [4, 3, 2])  # 自底部向上：hop3、hop2、hop1
        self.assertEqual(len(set(positions)), 3)
        self.assertTrue(all(m["matched"] for m in sig["matches"]))

    def test_repeated_h_entry_consumes_distinct_copies_in_list_order(self):
        # From 列两次、两个实际 From：先匹配底部（pos 4）再匹配上方（pos 3）
        raw = (
            "DKIM-Signature: d=e.com; h=From:From; b=x\n"
            "From: first@b.c\nFrom: second@b.c\n"
        )
        sig = analyze_dkim_coverage(raw)["signatures"][0]
        self.assertEqual([m["position"] for m in sig["matches"]], [3, 2])
        # 两个副本都被覆盖
        self.assertEqual(sig["uncovered_targets"], [])

    def test_more_h_entries_than_copies_leaves_last_unmatched(self):
        raw = (
            "DKIM-Signature: d=e.com; h=Received:Received:Received; b=x\n"
            "Received: by only1\n"
            "Received: by only2\n"
        )
        sig = analyze_dkim_coverage(raw)["signatures"][0]
        self.assertTrue(sig["matches"][0]["matched"])
        self.assertTrue(sig["matches"][1]["matched"])
        self.assertFalse(sig["matches"][2]["matched"])
        self.assertIsNone(sig["matches"][2]["position"])
        unmatched = sig["unmatched_entries"]
        self.assertEqual([u["name"] for u in unmatched], ["Received"])
        self.assertEqual(unmatched[0]["index"], 2)

    def test_unmatched_does_not_block_later_entries(self):
        # 中间的 X-Missing 无对应字段，后续 Subject 仍应正常匹配
        raw = dkim(
            "From:X-Missing:Subject",
            "From: a@b.c\nSubject: s\n",
        )
        sig = analyze_dkim_coverage(raw)["signatures"][0]
        statuses = [(m["name"], m["matched"]) for m in sig["matches"]]
        self.assertEqual(
            statuses, [("From", True), ("X-Missing", False), ("Subject", True)]
        )


class UncoveredTargetTests(unittest.TestCase):
    def test_extra_subject_below_signature_is_uncovered_copy(self):
        # 转发方在顶部签名后又追加一个 Subject：两条签名都只覆盖原始 Subject
        raw = (
            "DKIM-Signature: d=relay.example; h=Subject; b=x\n"
            "Subject: injected later\n"
            "DKIM-Signature: d=example.com; h=Subject; b=y\n"
            "Subject: original\n"
        )
        result = analyze_dkim_coverage(raw)
        outer, inner = result["signatures"]
        # 外部签名：注入的 Subject 在其下方，未覆盖
        self.assertEqual(outer["matches"][0]["position"], 4)
        groups = {g["field"]: g for g in outer["uncovered_targets"]}
        self.assertIn("Subject", groups)
        self.assertEqual(groups["Subject"]["total_count"], 2)
        self.assertEqual(groups["Subject"]["uncovered_count"], 1)
        copy = groups["Subject"]["copies"][0]
        self.assertEqual(copy["position"], 2)
        self.assertEqual(copy["relative"], "below")
        self.assertEqual(copy["value"], "injected later")
        # 内部签名：注入字段在其上方（签名之后、上方追加）
        groups = {g["field"]: g for g in inner["uncovered_targets"]}
        copy = groups["Subject"]["copies"][0]
        self.assertEqual(copy["position"], 2)
        self.assertEqual(copy["relative"], "above")
        self.assertEqual(inner["matches"][0]["position"], 4)

    def test_each_signature_audited_independently(self):
        # 同名签名之间互不干扰：各自独立维护“已使用”集合
        raw = (
            "DKIM-Signature: d=a.example; h=From:X-One; b=x\n"
            "X-One: 1\n"
            "DKIM-Signature: d=b.example; h=From:X-Two; b=y\n"
            "X-Two: 2\nFrom: a@b.c\n"
        )
        result = analyze_dkim_coverage(raw)
        self.assertEqual(result["signature_count"], 2)
        a_sig, b_sig = result["signatures"]
        self.assertEqual(
            [(m["name"], m["position"]) for m in a_sig["matches"]],
            [("From", 5), ("X-One", 2)],
        )
        self.assertEqual(
            [(m["name"], m["position"]) for m in b_sig["matches"]],
            [("From", 5), ("X-Two", 4)],
        )

    def test_from_subject_to_date_uncovered_listed_per_copy(self):
        # 两个 To：h= 只列一次 → 底部副本被覆盖，另一个作为未覆盖副本列出
        raw = dkim(
            "From:To:Subject:Date",
            "Date: d\nFrom: f\nTo: first-to\nTo: second-to\nSubject: s\n",
        )
        sig = analyze_dkim_coverage(raw)["signatures"][0]
        groups = {g["field"]: g for g in sig["uncovered_targets"]}
        self.assertEqual(set(groups), {"To"})
        self.assertEqual(groups["To"]["total_count"], 2)
        self.assertEqual(groups["To"]["uncovered_count"], 1)
        self.assertEqual(groups["To"]["copies"][0]["value"], "first-to")
        self.assertEqual(sig["target_uncovered_count"], 1)


class SignatureSelfExclusionTests(unittest.TestCase):
    def test_self_signature_not_in_match_pool(self):
        # h=DKIM-Signature 但只有本条签名字段 → 未匹配
        raw = "DKIM-Signature: d=e.com; h=DKIM-Signature; b=x\n"
        sig = analyze_dkim_coverage(raw)["signatures"][0]
        self.assertFalse(sig["matches"][0]["matched"])

    def test_nested_signature_can_be_referenced(self):
        raw = (
            "DKIM-Signature: d=outer; h=DKIM-Signature:Received:Received; b=x\n"
            "Received: by second\n"
            "DKIM-Signature: d=inner; h=From; b=y\n"
            "Received: by first\nFrom: a@b.c\n"
        )
        outer = analyze_dkim_coverage(raw)["signatures"][0]
        self.assertEqual(
            [(m["name"], m["position"]) for m in outer["matches"]],
            [("DKIM-Signature", 3), ("Received", 4), ("Received", 2)],
        )


class MalformedHTests(unittest.TestCase):
    def _sig(self, raw):
        return analyze_dkim_coverage(raw)["signatures"][0]

    def test_missing_h_tag_is_anomaly(self):
        sig = self._sig("DKIM-Signature: v=1; d=e.com; b=xx\nFrom: a@b.c\n")
        codes = [a["code"] for a in sig["anomalies"]]
        self.assertIn("missing_h", codes)
        self.assertEqual(sig["h_count"], 0)
        self.assertEqual(sig["matches"], [])
        self.assertEqual(sig["matched_count"], 0)

    def test_empty_h_tag_is_anomaly(self):
        for hval in ("", " ", "   "):
            sig = self._sig(
                f"DKIM-Signature: d=e.com; h={hval}; b=xx\nFrom: a@b.c\n"
            )
            self.assertIn("empty_h", [a["code"] for a in sig["anomalies"]])

    def test_duplicate_h_tag_is_anomaly(self):
        sig = self._sig(
            "DKIM-Signature: h=From; h=Subject; d=e.com; b=x\n"
            "From: a\nSubject: b\n"
        )
        self.assertIn("duplicate_h", [a["code"] for a in sig["anomalies"]])

    def test_anomaly_count_aggregated(self):
        raw = (
            "DKIM-Signature: d=ok.com; h=From; b=x\nFrom: a@b.c\n"
            "DKIM-Signature: d=bad.com; b=x\n"
        )
        result = analyze_dkim_coverage(raw)
        self.assertEqual(result["signature_count"], 2)
        self.assertEqual(result["anomaly_count"], 1)


class SampleTests(unittest.TestCase):
    def test_sample_audit(self):
        result = analyze_dkim_coverage(SAMPLE_HEADERS_DKIM)
        self.assertEqual(result["status"], "audited")
        self.assertEqual(result["signature_count"], 2)
        self.assertEqual(result["anomaly_count"], 0)
        outer, inner = result["signatures"]
        self.assertEqual(outer["domain"], "relay.provider.example")
        # h= 中 To 出现两次但只有一个实际 To
        self.assertEqual(outer["matched_count"], 7)
        self.assertEqual(
            [u["name"] for u in outer["unmatched_entries"]], ["To"]
        )
        # 顶部追加的 Subject 未被外部签名覆盖
        outer_subj = next(
            g for g in outer["uncovered_targets"] if g["field"] == "Subject"
        )
        self.assertEqual(outer_subj["uncovered_count"], 1)
        self.assertEqual(outer_subj["copies"][0]["position"], 2)
        # 内部签名缺 Content-Type → 未匹配；注入 Subject 在其上方
        self.assertEqual(
            [u["name"] for u in inner["unmatched_entries"]], ["Content-Type"]
        )
        inner_subj = next(
            g for g in inner["uncovered_targets"] if g["field"] == "Subject"
        )
        self.assertEqual(inner_subj["copies"][0]["relative"], "above")
        # 三个 Received 被逐条覆盖（不按集合合并）
        recv = [m for m in outer["matches"] if m["name"] == "Received"]
        self.assertEqual(len(recv), 3)
        self.assertEqual(len({m["position"] for m in recv}), 3)


@unittest.skipIf(create_app is None, "未安装 Flask")
class DkimApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_coverage_success_same_structure(self):
        resp = self.client.post(
            "/api/dkim/coverage", json={"headers": SAMPLE_HEADERS_DKIM}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data, analyze_dkim_coverage(SAMPLE_HEADERS_DKIM))
        self.assertEqual(data["status"], "audited")
        self.assertEqual(data["signature_count"], 2)

    def test_api_no_signature_returns_none(self):
        resp = self.client.post(
            "/api/dkim/coverage", json={"headers": "Subject: hi\nFrom: a@b.c\n"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "none")
        self.assertEqual(data["status_label"], "无 DKIM 签名")

    def test_api_empty_returns_400(self):
        resp = self.client.post("/api/dkim/coverage", json={"headers": "  "})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_api_non_string_returns_400(self):
        resp = self.client.post("/api/dkim/coverage", json={"headers": 123})
        self.assertEqual(resp.status_code, 400)

    def test_api_oversize_returns_400(self):
        app = create_app()
        app.config["MAX_INPUT_BYTES"] = 1024
        client = app.test_client()
        resp = client.post(
            "/api/dkim/coverage", json={"headers": "x" * 4096}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("KB", resp.get_json()["error"])

    def test_api_form_field_accepted(self):
        resp = self.client.post(
            "/api/dkim/coverage", data={"headers": SAMPLE_HEADERS_DKIM}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "audited")

    def test_form_page_renders_signatures(self):
        resp = self.client.post(
            "/dkim-coverage", data={"headers_dkim": SAMPLE_HEADERS_DKIM}
        )
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("DKIM h= 头字段覆盖审计结果", html)
        self.assertIn("relay.provider.example", html)
        self.assertIn("未匹配", html)
        self.assertIn("h= 字段名", html)

    def test_form_page_none_banner(self):
        resp = self.client.post(
            "/dkim-coverage", data={"headers_dkim": "Subject: hi\n"}
        )
        html = resp.get_data(as_text=True)
        self.assertIn("无 DKIM 签名", html)

    def test_index_page_has_dkim_section(self):
        resp = self.client.get("/")
        html = resp.get_data(as_text=True)
        self.assertIn("DKIM 头字段覆盖审计", html)
        self.assertIn("/api/dkim/coverage", html)


if __name__ == "__main__":
    unittest.main()
