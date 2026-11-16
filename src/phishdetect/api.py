"""FastAPI service and static single-page UI, with no URL network access."""
import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .inference import Detector


class PredictionRequest(BaseModel):
    url: str = Field(min_length=1, max_length=8192)


def create_app(model_path: Path | None = None) -> FastAPI:
    """Construct an app; missing model gives useful health and 503 responses."""
    @asynccontextmanager
    async def lifespan(app):
        path = model_path or Path(os.getenv('PHISHDETECT_MODEL', 'models/phish_model.joblib'))
        app.state.detector = Detector(path) if path.exists() else None
        yield

    app = FastAPI(title='PhishDetect', version='0.2.0', lifespan=lifespan)
    static = Path(__file__).parent / 'static'
    app.mount('/static', StaticFiles(directory=static), name='static')

    @app.get('/')
    def index():
        return FileResponse(static / 'index.html')

    @app.get('/health')
    def health():
        detector = app.state.detector
        return {'status': 'ready' if detector else 'model_missing', 'model_loaded': detector is not None,
                'network_url_analysis': False}

    @app.post('/predict')
    def predict(request: PredictionRequest):
        if not app.state.detector:
            raise HTTPException(503, 'Model missing. Run python tasks.py train first.')
        try:
            return app.state.detector.predict(request.url)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    return app


app = create_app()
