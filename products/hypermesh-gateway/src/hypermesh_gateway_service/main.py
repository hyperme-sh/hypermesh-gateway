import os

import uvicorn


def main() -> None:
    from api.infrastructure.metrics import start_metrics_server

    start_metrics_server()
    from hypermesh_gateway_service.app import app

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
