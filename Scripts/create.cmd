gcloud compute networks create "datalab-network" --project "datalab-159405" --description "Network for Datalab servers"

  gcloud compute firewall-rules create datalab-network-allow-ssh  --project "datalab-159405"  --allow tcp:22  --network "datalab-network" --description "Allow SSH access"

  gsutil cp gs://cloud-datalab/server.yaml ./datalab-server.yaml

  gcloud compute instances create "datalab-159405-us-central1-a-1" --project "datalab-159405" --zone "us-central1-a"  --network "datalab-network" --image-family "container-vm" --image-project "google-containers" --metadata-from-file "google-container-manifest=datalab-server.yaml" --machine-type "n1-highmem-2" --scopes "cloud-platform"

  gcloud compute ssh --quiet --project "datalab-159405" --zone "us-central1-a" --ssh-flag="-N" --ssh-flag="-L" --ssh-flag="localhost:8081:localhost:8080" "niteshsingh@datalab-159405-vm-1"