export function createMonotonicClock(systemClock = () => Date.now()) {
  let highWaterMark = systemClock();

  return function now() {
    const current = systemClock();
    if (current > highWaterMark) {
      highWaterMark = current;
    }
    return highWaterMark;
  };
}
