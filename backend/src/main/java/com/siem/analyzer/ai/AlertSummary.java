package com.siem.analyzer.ai;

import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.Severity;
import dev.langchain4j.model.output.structured.Description;
import java.util.List;

public record AlertSummary(
        @Description(
                        "One to eight values copied character for character from the alert that the"
                                + " assessment rests on: addresses, paths, user names, status codes,"
                                + " counts, user agents or message fragments. Copy them exactly as"
                                + " they appear; never paraphrase, complete or invent one")
                List<String> evidence,
        @Description(
                        "How serious the alert is once the evidence is weighed: CRITICAL for an attack"
                                + " that likely succeeded or is ongoing against a sensitive target,"
                                + " ERROR for a real attack attempt, WARNING for probing or a"
                                + " plausible attempt, INFO for activity that is almost certainly"
                                + " benign, DEBUG only for noise")
                Severity severity,
        @Description(
                        "The kind of attack the evidence points to; BENIGN when it looks like a false"
                                + " positive, OTHER when none of the values fits or the alert holds"
                                + " too little to tell")
                AttackType attackType,
        @Description(
                        "Two to four plain sentences for an analyst: what happened, from where,"
                                + " against what, and why it matters. Name concrete values (address,"
                                + " path, user, counts) only as the alert gives them, and say so when"
                                + " the alert does not show something, such as whether the attack"
                                + " succeeded")
                String summary,
        @Description(
                        "The next step an analyst should take, concrete and short, for example which"
                                + " address to block, which account to check or which log to review;"
                                + " any address or account it names must be one from the alert")
                String recommendedAction) {}
