"""Configuración compartida de Pydantic para todos los modelos."""

from pydantic import BaseModel, ConfigDict


class GodTierBaseModel(BaseModel):
    """Base común para todos los modelos del sistema.

    NOTA: NO usamos validate_assignment=True porque combinado con
    field_validator(mode="after") que asigna self.value causa recursión infinita.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=False,
        use_enum_values=False,
        arbitrary_types_allowed=False,
        populate_by_name=True,
    )
