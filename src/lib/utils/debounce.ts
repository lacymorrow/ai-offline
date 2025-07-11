// @ts-nocheck
/* eslint-disable-all */

// Remove the import statement for Timeout
// import { Timeout } from 'node';

// Add a type annotation for startIndex
export function restArguments<T extends any[], R>(
	func: (...args: [...T, ...R[]]) => any,
	startIndex: number = func.length - 1
) {
	return function (this: any, ...args: T) {
		const length = Math.max(args.length - startIndex, 0);
		const rest = Array(length);
		let index = 0;
		for (; index < length; index += 1) {
			rest[index] = args[index + startIndex];
		}
		switch (startIndex) {
			case 0:
				return func.call(this, rest) as R;
			case 1:
				return func.call(this, args[0], rest) as R;
			case 2:
				return func.call(this, args[0], args[1], rest) as R;
			default: {
				const _args: [...T, R[]] = Array(startIndex + 1) as [...T, R[]];
				for (index = 0; index < startIndex; index += 1) {
					_args[index] = args[index];
				}
				_args[startIndex] = rest;
				return func.apply(this, _args) as R;
			}
		}
	};
}

// Add type annotation for this
export function debounce<T extends any[], R>(
	func: (...args: T) => R,
	wait: number,
	immediate?: boolean
) {
	let timeout: NodeJS.Timeout | null;
	let previous: number;
	let args: T | undefined;
	let result: R | undefined;
	let context: any;

	const now = () => Date.now();

	const later = function (this: any) {
		const passed = now() - previous;
		if (wait > passed) {
			// Ensure timeout value is never negative
			const remainingWait = Math.max(wait - passed, 0);
			timeout = setTimeout(later, remainingWait);
		} else {
			timeout = null;
			if (!immediate) {
				result = func.apply(context, args!);
			}
			if (!timeout) {
				args = context = undefined;
			}
		}
	};

	const debounced = restArguments(function (this: any, _args: T) {
		// eslint-disable-next-line @typescript-eslint/no-this-alias
		context = this;
		args = _args;
		previous = now();
		if (!timeout) {
			timeout = setTimeout(later, wait);
			if (immediate) {
				result = func.apply(context, args);
			}
		}
		return result;
	});

	// Add cancel property
	debounced.cancel = function (this: any) {
		clearTimeout(timeout!);
		timeout = args = context = undefined;
	};

	return debounced;
}
