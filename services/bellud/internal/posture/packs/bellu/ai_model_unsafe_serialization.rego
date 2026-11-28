package bellu.bellu.ai_model_unsafe_serialization

import rego.v1

# An AI model stored in a format that can run code when loaded. The formats
# come from input.data.ai_unsafe_formats (loaded from ai-signatures.yaml); when
# that is not supplied the default list below applies. The ai_model attribute
# `serialization_format` holds the lower-case format name (for example pickle).
default_formats := ["pickle", "pkl", "joblib", "dill", "cloudpickle", "pt", "pth", "ckpt", "bin", "npy", "npz", "h5", "keras", "marshal"]

formats := input.data.ai_unsafe_formats

formats := default_formats if not input.data.ai_unsafe_formats

violation contains {"evidence": {"rule": input.id, "format": f}} if {
	f := lower(input.attributes.serialization_format)
	f in {lower(x) | some x in formats}
}
