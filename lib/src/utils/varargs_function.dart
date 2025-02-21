class VarargsFunction {
  const VarargsFunction(
    this.onCall,
  );

  final dynamic Function(List arguments) onCall;
}