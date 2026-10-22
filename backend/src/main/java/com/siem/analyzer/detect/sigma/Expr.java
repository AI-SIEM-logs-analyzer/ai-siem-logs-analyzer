package com.siem.analyzer.detect.sigma;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

sealed interface Expr {

    record Leaf(String text) implements Expr {
        public Leaf {
            Objects.requireNonNull(text, "text");
        }
    }

    record And(List<Expr> operands) implements Expr {
        public And {
            operands = List.copyOf(operands);
        }
    }

    record Or(List<Expr> operands) implements Expr {
        public Or {
            operands = List.copyOf(operands);
        }
    }

    record Not(Expr operand) implements Expr {
        public Not {
            Objects.requireNonNull(operand, "operand");
        }
    }

    static Expr leaf(String text) {
        return new Leaf(text);
    }

    static Expr and(List<Expr> operands) {
        List<Expr> flat = new ArrayList<>();
        for (Expr operand : operands) {
            if (operand instanceof And and) {
                flat.addAll(and.operands());
            } else {
                flat.add(operand);
            }
        }
        return flat.size() == 1 ? flat.get(0) : new And(flat);
    }

    static Expr or(List<Expr> operands) {
        List<Expr> flat = new ArrayList<>();
        for (Expr operand : operands) {
            if (operand instanceof Or or) {
                flat.addAll(or.operands());
            } else {
                flat.add(operand);
            }
        }
        return flat.size() == 1 ? flat.get(0) : new Or(flat);
    }

    static Expr not(Expr operand) {
        return operand instanceof Not not ? not.operand() : new Not(operand);
    }

    default String render() {
        StringBuilder text = new StringBuilder();
        render(this, 0, text);
        return text.toString();
    }

    private static void render(Expr expr, int context, StringBuilder text) {
        int precedence = precedence(expr);
        boolean parenthesize = precedence < context;
        if (parenthesize) {
            text.append('(');
        }
        switch (expr) {
            case Leaf leaf -> text.append(leaf.text());
            case Not not -> {
                text.append("not ");
                render(not.operand(), precedence, text);
            }
            case And and -> join(and.operands(), " and ", precedence, text);
            case Or or -> join(or.operands(), " or ", precedence, text);
        }
        if (parenthesize) {
            text.append(')');
        }
    }

    private static void join(
            List<Expr> operands, String separator, int context, StringBuilder text) {
        for (int i = 0; i < operands.size(); i++) {
            if (i > 0) {
                text.append(separator);
            }

            render(operands.get(i), context + 1, text);
        }
    }

    private static int precedence(Expr expr) {
        return switch (expr) {
            case Or or -> 1;
            case And and -> 2;
            case Not not -> 3;
            case Leaf leaf -> 4;
        };
    }
}
