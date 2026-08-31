"""Decommissioned candidate-side release-authority diagnostic."""


def main() -> int:
    print(
        '{"authority_decision_attempted":false,'
        '"authority_integration":"absent",'
        '"external_material_read":false,'
        '"format":"financial-planning-sdk-br.external-authority-diagnostic.v1",'
        '"release_authorized":false,'
        '"status":"external_authority_not_implemented"}'
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
