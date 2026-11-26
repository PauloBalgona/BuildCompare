from flask import Blueprint, render_template

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def landing():
    categories = []
    popular_materials = []
    featured_stores = []

    return render_template(
        "pages/landing.html",
        categories=categories,
        popular_materials=popular_materials,
        featured_stores=featured_stores,
    )