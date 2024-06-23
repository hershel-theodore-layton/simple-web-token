# simple-web-token

_An implementation of the Simple Web Token specification._

### License

This code is licensed under the [MIT License](./LICENSE), but note,
this code implements the Simple Web Token specification.

The Simple Web Token specification version 0.9.5.1, which can be found [here](<https://learn.microsoft.com/en-us/previous-versions/azure/azure-services/hh781551(v=azure.100)?redirectedfrom=MSDN>),
is licensed under the [Open Web Foundation Agreement Version 0.9](https://www.openwebfoundation.org/the-agreements/the-owf-0-9-agreements-necessary-claims/open-web-foundation-agreement-0-9).
This license is permissive, as long as you do not take
non-defensive patent legal action against implementers of the specification.
This also applies to this implementation (and implementer).

### Acknowledgments

The Simple Web Token specification has been authored by:

- Dick Hardt (dick.hardt@microsoft.com), Editor
- Yaron Goland (yarong@microsoft.com)

The implementation of SHA-256 in Hack was heavily based on amosnier's C implementation.
This Hack implementation can be found [here](https://github.com/hershel-theodore-layton/simple-web-token/blob/master/src/_Private/sha256.c.hack).
The implementation in C can be found [here](https://github.com/amosnier/sha-2/tree/b29613850d6e54e7159197ef42c7d22d012b6367).
The C code is licensed under `The Unlicense` or `BSD-0-Clause` at your option.
Both licenses are public domain equivalent and do not require attribution.
Thank you Amosnier, porting it was a pleasant experience.

I believe to have met the requirements imposed on me by the third-party licenses.
If you spot a violation of any third-party licenses in under this Github namespace,
you may notify me by filing a Github Issue on the affected projects.
