"""Named-argument frontend for the verified Cursor bulk-read executor."""
import argparse
import sys

from mcp_portal import delegate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--paths', nargs='+', required=True)
    parser.add_argument('--question', required=True)
    parser.add_argument('--model', default=None)
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()
    try:
        model, decision = delegate.resolve_model(args.model)
        print(decision['reason'], file=sys.stderr)
        request = delegate.build_request(args.root, args.paths, args.question, model, args.timeout)
        result = delegate.execute(request, model_reason=decision['reason'])
        if request != delegate.build_request(args.root, args.paths, args.question, model, args.timeout):
            raise delegate.Refused('SOURCE_CHANGED')
        sys.stdout.buffer.write(delegate.encoded(result) + b'\n')
        return 0
    except (delegate.Refused, ValueError, OSError, KeyError, TypeError) as exc:
        error = str(exc) if isinstance(exc, delegate.Refused) else type(exc).__name__
        sys.stdout.buffer.write(delegate.encoded({'status': 'FAIL', 'error': error}) + b'\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
