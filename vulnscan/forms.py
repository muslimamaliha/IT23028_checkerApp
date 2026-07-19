from django import forms

class PackageScanForm(forms.Form):
    package_input = forms.CharField(
        label="Package", max_length=200,
        widget=forms.TextInput(attrs={
            "placeholder": "e.g. lodash or lodash@4.17.15",
            "autocomplete": "off",
        }),
    )

    def parse(self):
        raw = self.cleaned_data["package_input"].strip()
        if raw.startswith("@"):
            parts = raw.split("@")
            name = "@" + parts[1]
            version = parts[2] if len(parts) > 2 else None
        elif "@" in raw:
            name, version = raw.split("@", 1)
        else:
            name, version = raw, None
        return name, version
