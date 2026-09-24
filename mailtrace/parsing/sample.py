"""页面“填入示例”按钮使用的示例邮件头。"""

SAMPLE_HEADERS = """\
Return-Path: <sender@example.com>
Received: from mailbox.final.example (127.0.0.1)
	by mailbox.final.example (Dovecot) with LMTP id zX92kQ
	for <user@final.example>; Tue, 23 Sep 2026 10:02:10 +0800 (CST)
Received: from mx1.final.example (mx1.final.example [198.51.100.10])
	by mailbox.final.example (Postfix) with ESMTPS id 7F3A2C9
	for <user@final.example>; Tue, 23 Sep 2026 10:02:10 +0800
Received: from relay2.provider.example (relay2.provider.example [203.0.113.22])
	by mx1.final.example (Postfix) with ESMTP id B4D91
	for <user@final.example>; Tue, 23 Sep 2026 10:02:05 +0800
Received: from relay1.provider.example (relay1.provider.example
	[203.0.113.11])
	by relay2.provider.example (Postfix) with ESMTP id 99C10
	for <user@final.example>; Tue, 23 Sep 2026 02:01:55 +0000 (UTC)
Received: from outgoing.example.org (outgoing.example.org [192.0.2.50])
	by relay1.provider.example (Postfix) with ESMTP id 41AB8
	for <user@final.example>; Tue, 23 Sep 2026 02:01:30 +0000
Received: from smtp01.corp.example.net (smtp01.corp.example.net [10.10.0.5])
	by outgoing.example.org with ESMTP
	for user@final.example
Received: from [10.10.0.5] (helo=smtp01.corp.example.net)
	by smtp01.corp.example.net with ESMTP id 88FF21
	for user@final.example; not-a-valid-date (server clock lost)
Date: Tue, 23 Sep 2026 02:00:00 +0000
From: Sender <sender@example.com>
To: User <user@final.example>
Subject: Delivery path demo
	with folding
Message-ID: <demo@example.com>
"""

# 对照示例（B 侧）：与 SAMPLE_HEADERS 同一条投递链路，但
# - 开头多一跳 smtp00 -> smtp01（新增节点，且与既有 smtp01 同名，演示保序对齐）；
# - 末尾少了 Dovecot LMTP 一跳（缺失节点）；
# - 各跳时间不同（演示相邻耗时差值），smtp01 一跳时间有效而 A 侧无效（不可比较）。
SAMPLE_HEADERS_B = """\
Return-Path: <sender@example.com>
Received: from mx1.final.example (mx1.final.example [198.51.100.10])
	by mailbox.final.example (Postfix) with ESMTPS id 8C11D2
	for <user@final.example>; Tue, 23 Sep 2026 10:02:12 +0800
Received: from relay2.provider.example (relay2.provider.example [203.0.113.22])
	by mx1.final.example (Postfix) with ESMTP id C5E20
	for <user@final.example>; Tue, 23 Sep 2026 10:02:06 +0800
Received: from relay1.provider.example (relay1.provider.example [203.0.113.11])
	by relay2.provider.example (Postfix) with ESMTP id A1B33
	for <user@final.example>; Tue, 23 Sep 2026 02:01:58 +0000 (UTC)
Received: from outgoing.example.org (outgoing.example.org [192.0.2.50])
	by relay1.provider.example (Postfix) with ESMTP id 55BC9
	for <user@final.example>; Tue, 23 Sep 2026 02:01:33 +0000
Received: from smtp01.corp.example.net (smtp01.corp.example.net [10.10.0.5])
	by outgoing.example.org with ESMTP id 77D21
	for user@final.example; Tue, 23 Sep 2026 02:00:40 +0000
Received: from [10.10.0.5] (helo=smtp01.corp.example.net)
	by smtp01.corp.example.net with ESMTP id 91AA02
	for user@final.example; Tue, 23 Sep 2026 02:00:12 +0000
Received: from smtp00.corp.example.net (smtp00.corp.example.net [10.10.0.9])
	by smtp01.corp.example.net with ESMTP id 02BB77
	for user@final.example; Tue, 23 Sep 2026 02:00:05 +0000
Date: Tue, 23 Sep 2026 02:00:00 +0000
From: Sender <sender@example.com>
To: User <user@final.example>
Subject: Delivery path demo
"""


# 多封慢段归因示例：三封走同一条 edge -> mid -> final 链路的邮件，
# 用页面规范分隔符 BATCH_DELIMITER（===== 下一封邮件 =====）分开。
# - 邮件 1：正常投递，mid->final 段耗时 150 秒；
# - 邮件 2：edge->mid 耗时 600 秒（最慢段），mid->final 时间倒灌 -20 秒（排除）；
# - 邮件 3：mid->final 段时间无效（排除）；退信后发件方从同一 IP 重新注入，
#   edge->mid 同键区段在本封内出现两次（60 秒、150 秒），仅取最大有效
#   非负耗时 150 秒作为该邮件样本；退信/重注入路径另有仅本封出现的
#   mid->edge 回流段（60 秒）。
SAMPLE_HEADERS_BATCH = """\
Received: from mid.example (mid.example [198.51.100.20])
\tby final.example with ESMTP id M1C
\t; Tue, 23 Sep 2026 02:06:30 +0000
Received: from edge.example (edge.example [198.51.100.10])
\tby mid.example with ESMTP id M1B
\t; Tue, 23 Sep 2026 02:04:00 +0000
Received: from sender.example (sender.example [203.0.113.50])
\tby edge.example with ESMTP id M1A
\t; Tue, 23 Sep 2026 02:03:00 +0000
Date: Tue, 23 Sep 2026 02:03:00 +0000
From: sender@example.com
To: user@final.example
Subject: batch message 1
===== 下一封邮件 =====
Received: from mid.example (mid.example [198.51.100.20])
\tby final.example with ESMTP id M2C
\t; Tue, 23 Sep 2026 02:13:40 +0000
Received: from edge.example (edge.example [198.51.100.10])
\tby mid.example with ESMTP id M2B
\t; Tue, 23 Sep 2026 02:14:00 +0000
Received: from sender.example (sender.example [203.0.113.50])
\tby edge.example with ESMTP id M2A
\t; Tue, 23 Sep 2026 02:04:00 +0000
Date: Tue, 23 Sep 2026 02:04:00 +0000
From: sender@example.com
To: user@final.example
Subject: batch message 2
===== 下一封邮件 =====
Received: from mid.example (mid.example [198.51.100.20])
\tby final.example with ESMTP id M3D
\t; not-a-valid-date (clock lost on final)
Received: from edge.example (edge.example [198.51.100.10])
\tby mid.example with ESMTP id M3C
\t; Tue, 23 Sep 2026 02:21:00 +0000
Received: from sender.example (sender.example [203.0.113.50])
\tby edge.example with ESMTP id M3B
\t; Tue, 23 Sep 2026 02:18:30 +0000
Received: from edge.example (edge.example [198.51.100.10])
\tby mid.example with ESMTP id M3A2
\t; Tue, 23 Sep 2026 02:17:30 +0000
Received: from sender.example (sender.example [203.0.113.50])
\tby edge.example with ESMTP id M3A
\t; Tue, 23 Sep 2026 02:16:30 +0000
Date: Tue, 23 Sep 2026 02:16:30 +0000
From: sender@example.com
To: user@final.example
Subject: batch message 3
"""

# ARC 链结构检查示例：完整的两实例 ARC 链（i=1 为首个实例，cv=none；
# i=2 为后续实例，cv=pass）。ARC 字段由接收方在顶部追加，因此原文中
# i=2 的字段组写在 i=1 之前；字段含折行，且 i=1 的 ARC-Seal 故意把
# cv 写在 i 前面（解析与标签书写顺序无关）。
SAMPLE_HEADERS_ARC = """\
ARC-Seal: i=2; a=rsa-sha256; t=1790216000; cv=pass;
\td=relay.provider.example; s=arc2026;
\tb=Pm9fKq2wRelaySealSignature==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed;
\td=relay.provider.example; s=arc2026; t=1790216000;
\tbh=3vBsRelayBodyHash==; h=From:To:Subject:Date;
\tb=Zq8wRelayMessageSignature==
ARC-Authentication-Results: i=2; relay.provider.example;
\tspf=pass smtp.mailfrom=example.com;
\tdkim=pass header.d=example.com; dmarc=pass header.from=example.com
ARC-Seal: cv=none; i=1; a=rsa-sha256; t=1790215940;
\td=mx.final.example; s=arc2026; b=Xy7zEdgeSealSignature==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
\td=mx.final.example; s=arc2026; t=1790215940;
\tbh=9wQzEdgeBodyHash==; h=From:To:Subject:Date;
\tb=Mn4vEdgeMessageSignature==
ARC-Authentication-Results: i=1; mx.final.example;
\tspf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com
Received: from relay.provider.example (relay.provider.example [203.0.113.22])
\tby mx.final.example with ESMTPS id A1B2C3
\tfor <user@final.example>; Thu, 24 Sep 2026 02:13:20 +0000
Date: Thu, 24 Sep 2026 02:12:40 +0000
From: Sender <sender@example.com>
To: User <user@final.example>
Subject: ARC chain demo
Message-ID: <arc-demo@example.com>
"""


# DKIM h= 覆盖审计示例（自头部顶部到底部）：
# - 两条嵌套 DKIM-Signature：外部转发方（d=relay.provider.example，pos 1）
#   与原始发件域（d=example.com，pos 4），h= 均折行书写；
# - 外部签名 h= 列出三次 Received（实际正好三个，按“从底部向上、各自
#   消费不同副本”逐一覆盖，重复字段名不合并）；To 列了两次但只有一个
#   实际 To → 第二个 To 为未匹配 h 项；
# - pos 2 多出一个 Subject（转发后追加 / 疑似注入）：两条签名从底部
#   向上匹配时都先消费 pos 10 的原始 Subject，pos 2 成为各自“未覆盖的
#   实际副本”（对内部签名它还位于签名上方）；
# - 内部签名 h= 包含 Content-Type，但头部中没有该字段 → 未匹配 h 项。
SAMPLE_HEADERS_DKIM = """\
DKIM-Signature: v=1; a=rsa-sha256; d=relay.provider.example;
\ts=relay2026; c=relaxed/relaxed; t=1790216200;
\th=From:Subject:To:To:Date:Received:Received:Received;
\tbh=cmVsYXlwbGFjZWhvbGRlcg==;
\tb=UmVsYXlGb3J3YXJkZXJT aWduYXR1cmU=
Subject: Urgent: please update payment details
Received: from mx.final.example (mx.final.example [198.51.100.10])
\tby relay.provider.example with ESMTPS id 7C3D91
\tfor <user@final.example>; Thu, 24 Sep 2026 02:14:30 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel2026;
\tc=relaxed/relaxed; t=1790216080;
\th=From:To:Subject:Date:Received:Received:Content-Type;
\tbh=b3JpZ2luYWxib2R5aGFzaA==;
\tb=T3JpZ2luYWxBdXRob3JT aWduYXR1cmU=
Received: from outgoing.example.org (outgoing.example.org [192.0.2.50])
\tby mx.final.example with ESMTP id 44AB8
\tfor <user@final.example>; Thu, 24 Sep 2026 02:14:00 +0000
Received: from smtp01.corp.example.net (smtp01.corp.example.net [10.10.0.5])
\tby outgoing.example.org with ESMTP id 88FF21
\tfor user@final.example; Thu, 24 Sep 2026 02:01:00 +0000
Date: Thu, 24 Sep 2026 02:00:00 +0000
From: Sender <sender@example.com>
To: User <user@final.example>
Subject: Monthly newsletter
Message-ID: <dkim-demo@example.com>
"""


