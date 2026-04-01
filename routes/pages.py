from datetime import date

from flask import Blueprint, render_template

bp = Blueprint("pages", __name__)


@bp.route("/")
def index():
    return render_template("index.html", today=date.today().isoformat())


@bp.route("/device/<path:mac>")
def device_detail(mac):
    return render_template("device.html", mac=mac, today=date.today().isoformat())


@bp.route("/domains")
def domains():
    return render_template("domains.html", today=date.today().isoformat())


@bp.route("/domain/<path:host>")
def domain_detail(host):
    return render_template("domain.html", host=host, today=date.today().isoformat())


@bp.route("/devices")
def devices():
    return render_template("devices.html", today=date.today().isoformat())


@bp.route("/policies")
def policies():
    return render_template("policies.html", today=date.today().isoformat())


@bp.route("/policy_group/<path:name>")
def policy_group_detail(name):
    return render_template("policy_group.html", name=name, today=date.today().isoformat())


@bp.route("/suspicious")
def suspicious():
    return render_template("suspicious.html", today=date.today().isoformat())
