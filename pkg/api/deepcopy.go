package api

func (in *PolicyRule) DeepCopyInto(out *PolicyRule) {
	*out = *in
	if in.Methods != nil {
		out.Methods = make([]string, len(in.Methods))
		copy(out.Methods, in.Methods)
	}
	if in.Inject != nil {
		out.Inject = new(InjectConfig)
		in.Inject.DeepCopyInto(out.Inject)
	}
}

func (in *PolicyRule) DeepCopy() *PolicyRule {
	if in == nil {
		return nil
	}
	out := new(PolicyRule)
	in.DeepCopyInto(out)
	return out
}

func (in *InjectConfig) DeepCopyInto(out *InjectConfig) {
	*out = *in
	if in.Headers != nil {
		out.Headers = make(map[string]string, len(in.Headers))
		for k, v := range in.Headers {
			out.Headers[k] = v
		}
	}
	if in.Query != nil {
		out.Query = make(map[string]string, len(in.Query))
		for k, v := range in.Query {
			out.Query[k] = v
		}
	}
}

func (in *SecretConfig) DeepCopyInto(out *SecretConfig) {
	*out = *in
}

func (in *SecretConfig) DeepCopy() *SecretConfig {
	if in == nil {
		return nil
	}
	out := new(SecretConfig)
	in.DeepCopyInto(out)
	return out
}

func (in *TenantConfig) DeepCopyInto(out *TenantConfig) {
	*out = *in
	if in.Policies != nil {
		out.Policies = make([]PolicyRule, len(in.Policies))
		for i := range in.Policies {
			in.Policies[i].DeepCopyInto(&out.Policies[i])
		}
	}
	if in.Secrets != nil {
		out.Secrets = make([]SecretConfig, len(in.Secrets))
		copy(out.Secrets, in.Secrets)
	}
}
