package scanstore

import "testing"

func TestListDoesNotTreatResultsAsScanMetadata(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	meta := &ScanMeta{ID: "fixture", Status: "completed", Incomplete: true, Warnings: []string{"synthetic unavailable resource"}}
	if err := store.Save(meta); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveResults(meta.ID, &ScanResults{Meta: *meta}); err != nil {
		t.Fatal(err)
	}
	scans, err := store.List()
	if err != nil || len(scans) != 1 || scans[0].ID != meta.ID || !scans[0].Incomplete {
		t.Fatalf("result file became phantom scan: %+v %v", scans, err)
	}
}
