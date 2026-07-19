import requests
from django.shortcuts import render
from .forms import PackageScanForm
from . import ml_inference

def scan_view(request):
    context = {"form": PackageScanForm(), "result": None, "error": None}
    if request.method == "POST":
        form = PackageScanForm(request.POST)
        context["form"] = form
        if form.is_valid():
            name, version = form.parse()
            try:
                context["result"] = ml_inference.analyze_package(name, version)
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    context["error"] = f'Package "{name}" npm registry-te paoa jay ni।'
                else:
                    context["error"] = f"Registry/OSV error: {e}"
            except requests.exceptions.RequestException as e:
                context["error"] = f"Network error: {e}"
            except Exception as e:
                context["error"] = f"Error: {e}"
    return render(request, "vulnscan/scan.html", context)
