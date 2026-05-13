package incertkms

import wrapping "github.com/openbao/go-kms-wrapping/v2"

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	var localOptions []OptionFunc
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, o)
		case OptionFunc:
			localOptions = append(localOptions, to)
		}
	}

	// Parse the global options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "kms_url":
				opts.withKmsUrl = v
			case "kms_username":
				opts.withKmsUsername = v
			case "kms_password":
				opts.withKmsPassword = v
			case "kms_key":
				opts.withKmsKey = v
			case "kms_vslot":
				opts.withKmsVSlot = v
			case "kms_key_name":
				opts.withKmsKeyName = v
			}
		}
	}

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}

	return &opts, nil
}

type OptionFunc func(*options) error

type options struct {
	*wrapping.Options

	withKmsUrl      string
	withKmsUsername string
	withKmsPassword string
	withKmsKey      string
	withKmsVSlot    string
	withKmsKeyName  string
}

func getDefaultOptions() options {
	return options{
		withKmsUrl: "https://kms-uat.incert.lu/kms",
	}
}

func WithKmsUrl(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKmsUrl = with
			return nil
		})
	}
}

func WithKmsUsername(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKmsUsername = with
			return nil
		})
	}
}

func WithKmsPassword(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKmsPassword = with
			return nil
		})
	}
}

func WithKmsKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKmsKey = with
			return nil
		})
	}
}

func WithKmsVSlot(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKmsVSlot = with
			return nil
		})
	}
}

func WithKmsKeyName(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKmsKeyName = with
			return nil
		})
	}
}
