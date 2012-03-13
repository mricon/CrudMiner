	function TWVersion() {
		// Set the development branch.  Valid are:
		//   stable   : Represents stable releases.
		//   unstable : Represents candidate and test/development releases.
		//   trunk     : Represents next generation development version.
		$this->branch 	= 'stable';

		// Set everything else, including defaults.
		$this->version 	= '6.4';
		$this->star	= 'Rigel';
		$this->releases	= array();

		// Check for Subversion or not
		$this->svn	= is_dir('.svn') ? 'y' : 'n';
	}
