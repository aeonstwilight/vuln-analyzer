from fastapi import File, Form, HTTPException, UploadFile

from core import load_asset_context


async def ver_options(
    asset_context: UploadFile = File(None),
    assume_internet_reachable: bool = Form(False),
    default_impact: int = Form(3),
    epss_threshold: float = Form(0.10),
) -> dict:
    """
    Form fields for the FedRAMP 2026 profiles, shared by every endpoint that
    runs the analysis pipeline. Ignored by the severity-based profiles.
    """
    context = None
    if asset_context is not None and asset_context.filename:
        try:
            context = load_asset_context(await asset_context.read())
        except Exception as e:
            raise HTTPException(400, f"Could not read asset context CSV: {e}")

    return {
        "asset_context": context,
        "assume_reachable": assume_internet_reachable,
        "default_impact": default_impact,
        "epss_threshold": epss_threshold,
    }
