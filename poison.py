print('This is the poison file.')

print(__file__)

print('Beginning execution of the original file.')

with open(__file__,'r') as f:
    exec(f.read())

print('Finished execution of the original file.')
