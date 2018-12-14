var e = "function" == typeof Object.assign ? Object.assign : function (a, b) {
        for (var c = 1; c < arguments.length; c++) {
            var d = arguments[c];
            if (d)
                for (var f in d) Object.prototype.hasOwnProperty.call(d, f) && (a[f] = d[f])
        }
        return a
    },
    g = "function" == typeof Object.defineProperties ? Object.defineProperty : function (a, b, c) {
        a != Array.prototype && a != Object.prototype && (a[b] = c.value)
    },
    h = "undefined" != typeof window && window === this ? this : "undefined" != typeof global && null != global ? global : this;

function k(a) {
    if (a) {
        for (var b = h, c = ["Object", "assign"], d = 0; d < c.length - 1; d++) {
            var f = c[d];
            f in b || (b[f] = {});
            b = b[f]
        }
        c = c[c.length - 1];
        d = b[c];
        a = a(d);
        a != d && null != a && g(b, c, {
            configurable: !0,
            writable: !0,
            value: a
        })
    }
}
k(function (a) {
    return a || e
});

function l(a, b, c, d, f) {
    this.location = a;
    this.c = b;
    this.mdDialog = d;
    this.f = f;
    n(this);
    a = a.search();
    if (a.expr && a.vars) try {
        var m = p(a.expr, a.vars);
        this.a = this.screen = "";
        q(this, m);
        this.b.ans = parseFloat(m) || 0
    } catch (v) {
        q(this, "Error")
    }
}
l.$inject = ["$location", "$http", "$httpParamSerializer", "$mdDialog", "vcRecaptchaService"];

function q(a, b) {
    a.screen = a.a ? a.screen + b : b
}

function n(a) {
    a.screen = "0";
    a.a = "";
    a.b = {
        pi: 3.14159,
        ans: 0
    }
}

function p(a, b) {
    a = String(a).toLowerCase();
    b = String(b);
    if (!/^(?:[\(\)\*\/\+%\-0-9 ]|\bvars\b|[.]\w+)*$/.test(a)) throw Error(a);
    b = JSON.parse(b, function (a, b) {
        if (b && "object" === typeof b && !Array.isArray(b)) return Object.assign(Object.create(null), b);
        if ("number" === typeof b) return b
    });
    return (new Function("vars", "return " + a))(b)
}

function r(a) {
    try {
        return p(a.a, JSON.stringify(a.b))
    } catch (b) {
        return "Error"
    }
}

function t(a) {
    var b = new URL("https://gcalc2.web.ctfcompetition.com");
    b.pathname = "/";
    b.searchParams.set("expr", a.a);
    b.searchParams.set("vars", JSON.stringify(a.b));
    return b + ""
}
l.prototype.permalink = function () {
    this.mdDialog.show(this.mdDialog.alert({
        title: "Link",
        htmlContent: t(this),
        ok: "Ok"
    }))
};
l.prototype.showCaptcha = function () {
    this.mdDialog.show({
        contentElement: "#captchaDialog",
        parent: angular.element(document.body)
    })
};
l.prototype.cloud = function () {
    var a = this.f.getResponse();
    a ? (this.c({
        method: "POST",
        url: "/report",
        data: {
            expr: this.a,
            vars: JSON.stringify(this.b),
            recaptcha: a
        }
    }), this.mdDialog.hide()) : alert("Wrong captcha.")
};
l.prototype.btnClick = function (a) {
    if (/[0-9.]/.test(a)) q(this, a), this.a += a;
    else if (/[*\/+%-]/.test(a)) q(this, " " + a + " "), this.a += a;
    else if (/[(]/.test(a)) q(this, " " + a), this.a += a;
    else if (/[)]/.test(a)) q(this, a + " "), this.a += a;
    else if ("\u03c0" == a) q(this, " \u03c0 "), this.a += " vars.pi";
    else switch (a) {
        case "ac":
            n(this);
            break;
        case "ans":
            q(this, " Ans ");
            this.a += " vars.ans";
            break;
        case "=":
            if (!this.a) break;
            a = r(this);
            this.a = this.screen = "";
            q(this, a);
            this.b.ans = parseFloat(a) || 0;
            break;
        case "pow":
            if (!this.a) break;
            a =
                r(this);
            a *= a;
            this.screen = "";
            this.a = parseFloat(a) || 0;
            q(this, a);
            this.b.ans = parseFloat(a) || 0;
            break;
        case "sqrt":
            this.a && (a = Math.sqrt(r(this)), this.screen = "", this.a = parseFloat(a) || 0, q(this, a), this.b.ans = parseFloat(a) || 0)
    }
};

function u(a) {
    a.html5Mode(!0)
}
u.$inject = ["$locationProvider"];
angular.module("calcApp", ["ngMaterial", "ngMessages", "ngSanitize", "vcRecaptcha"]).controller("CalcCtrl", l).config(u);