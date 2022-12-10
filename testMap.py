import gmaps
import json
import pandas as pd

with open('map.json', 'r') as file:
  mapDict = json.load(file)

df2 = pd.read_csv(r'/Users/zacharyburpee/GitHub/CloudComputing/addr.csv')

counts = [110000, 100, 1]
lat = [40.80918, 40.80949, 40.80851]
lon = [-73.95983, -73.96021, -73.96032]


#API Key = AIzaSyAXtGuFE0OAXBnUgpR90Wg7yC_bvHBCfrI
gmaps.configure(api_key="AIzaSyAXtGuFE0OAXBnUgpR90Wg7yC_bvHBCfrI")

heatmap_data = {'Counts': counts, 'latitude': lat, 'longitude' : lon} 
df = pd.DataFrame(data=heatmap_data) 
locations = df[['latitude', 'longitude']] 
weights = df['Counts'] 
fig = gmaps.figure() 
heatmap_layer = gmaps.heatmap_layer(locations, weights=weights) 
fig.add_layer(gmaps.heatmap_layer(locations, weights=weights)) 
fig
